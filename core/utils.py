from fastapi.responses import JSONResponse
from fastapi import status

def error_response(code = None, description = None, source = None, step = None, reason = None):
    _return_value = {
        "error": {
            "code": code,
            "description": description,
            "source": source,
            "step": step,
            "reason": reason
        }
    }
    return JSONResponse(content=_return_value)