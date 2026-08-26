import json

from app.push.fcm import (
    FcmSendError,
    build_fcm_send_error,
    is_permanently_invalid_fcm_token,
)


def _response(
    *,
    status: str,
    error_code: str | None = None,
    message: str = "Requested entity was not found.",
) -> str:
    details = []
    if error_code:
        details.append(
            {
                "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                "errorCode": error_code,
            }
        )
    return json.dumps(
        {
            "error": {
                "code": 404,
                "status": status,
                "message": message,
                "details": details,
            }
        }
    )


def test_unregistered_token_is_classified_as_permanently_invalid():
    error = build_fcm_send_error(
        404,
        _response(status="NOT_FOUND", error_code="UNREGISTERED"),
    )

    assert isinstance(error, FcmSendError)
    assert error.http_status == 404
    assert error.status == "NOT_FOUND"
    assert error.error_code == "UNREGISTERED"
    assert is_permanently_invalid_fcm_token(error) is True


def test_plain_not_found_does_not_invalidate_token():
    error = build_fcm_send_error(404, _response(status="NOT_FOUND"))

    assert error.error_code == ""
    assert is_permanently_invalid_fcm_token(error) is False


def test_invalid_argument_does_not_invalidate_token():
    error = build_fcm_send_error(
        400,
        _response(status="INVALID_ARGUMENT", error_code="INVALID_ARGUMENT"),
    )

    assert is_permanently_invalid_fcm_token(error) is False


def test_explicit_invalid_registration_token_is_permanently_invalid():
    error = build_fcm_send_error(
        400,
        _response(
            status="INVALID_ARGUMENT",
            error_code="INVALID_ARGUMENT",
            message="The registration token is not a valid FCM registration token",
        ),
    )

    assert is_permanently_invalid_fcm_token(error) is True


def test_malformed_error_response_remains_retryable():
    error = build_fcm_send_error(503, "upstream temporarily unavailable")

    assert error.http_status == 503
    assert error.error_code == ""
    assert is_permanently_invalid_fcm_token(error) is False
