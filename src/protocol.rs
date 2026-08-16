use serde::Serialize;

use crate::Error;

pub const SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Serialize)]
pub struct Success<T> {
    pub schema: u32,
    pub ok: bool,
    pub command: &'static str,
    pub data: T,
}

impl<T> Success<T> {
    pub fn new(command: &'static str, data: T) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            ok: true,
            command,
            data,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Failure<'a> {
    pub schema: u32,
    pub ok: bool,
    pub command: &'a str,
    pub error: FailureBody,
}

#[derive(Debug, Serialize)]
pub struct FailureBody {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}

impl<'a> Failure<'a> {
    pub fn from_error(command: &'a str, error: &Error) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            ok: false,
            command,
            error: FailureBody {
                code: error.code(),
                message: error.to_string(),
                retryable: matches!(error, Error::Io { .. }),
            },
        }
    }
}
