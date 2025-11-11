use pyo3::prelude::*;
use pyo3::types::PyDict;
use rand::RngCore;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: i32,
    pub exp: usize,
    pub jti: String,
}

#[pyclass]
pub struct RustToken {
    secret: String,
}

#[pymethods]
impl RustToken {
    #[new]
    pub fn new(secret: String) -> Self {
        RustToken { secret }
    }

    /// create token
    pub fn create_token(&self, user_id: i32, ttl_time: u64) -> PyResult<String> {
        let uuid = Uuid::new_v4();
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?
            .as_secs() + ttl_time;

        let claims = Claims {
            id: user_id,
            exp: exp as usize,
            jti: uuid.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(token)
    }

    /// decode token
    pub fn decode(&self, py: Python, token: &str) -> PyResult<PyObject> {
        let validation = Validation::default();

        let decoded: TokenData<Claims> = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let claims_value = serde_json::to_value(&decoded.claims)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let dict = PyDict::new(py);

        if let serde_json::Value::Object(map) = claims_value {
            for (key, value) in map {
                let py_val = match value {
                    serde_json::Value::String(s) => s.into_py(py),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            i.into_py(py)
                        } else if let Some(f) = n.as_f64() {
                            f.into_py(py)
                        } else {
                            n.to_string().into_py(py)
                        }
                    }
                    serde_json::Value::Bool(b) => b.into_py(py),
                    _ => value.to_string().into_py(py),
                };
                dict.set_item(key, py_val)?;
            }
        }

        Ok(dict.into_py(py))
    }

}

#[pyfunction]
/// generate random secret key
pub fn secret_key(py: Python) -> PyResult<PyObject> {
    let mut key = [0u8; 32]; // 32 bytes = 256 bits
    OsRng.fill_bytes(&mut key); // fill with random bytes
    let encoded = general_purpose::STANDARD.encode(key);
    Ok(encoded.to_object(py))
}



#[pymodule]
fn rustoken(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    let rusty_jwt_type = m.py().get_type::<RustToken>();
    m.add("RustToken", rusty_jwt_type)?;
    m.add_function(wrap_pyfunction!(secret_key, m)?)?;
    Ok(())
}
