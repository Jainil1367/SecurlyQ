"""BedrockGenerator tested against a stub boto3 client. No AWS account or network is used."""

import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError
from pydantic import ValidationError

from app.core.config import Settings
from app.llm.bedrock import BedrockGenerator, LLMUnavailable, build_generator


class StubClient:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.kwargs = response, error, None

    def converse(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


OK = {
    "output": {"message": {"role": "assistant", "content": [{"text": '{"a": '}, {"text": "1}"}]}},
    "usage": {"inputTokens": 321, "outputTokens": 45},
    "stopReason": "end_turn",
}


def gen(client):
    return BedrockGenerator("test-model-id", "us-east-1", timeout_seconds=5, max_tokens=500, client=client)


def test_request_shape_and_response_parsing():
    client = StubClient(OK)
    result = gen(client).generate("SYSTEM", "USER")
    assert client.kwargs["modelId"] == "test-model-id"
    assert client.kwargs["system"] == [{"text": "SYSTEM"}]
    assert client.kwargs["messages"] == [{"role": "user", "content": [{"text": "USER"}]}]
    assert client.kwargs["inferenceConfig"] == {"maxTokens": 500, "temperature": 0.2}  # bounded cost, low randomness
    assert result.text == '{"a": 1}' and (result.input_tokens, result.output_tokens) == (321, 45)


@pytest.mark.parametrize("code", ["ThrottlingException", "AccessDeniedException", "ModelNotReadyException", "ValidationException"])
def test_aws_errors_become_llm_unavailable_with_the_code(code):
    err = ClientError({"Error": {"Code": code, "Message": "details we do not want to leak"}}, "Converse")
    with pytest.raises(LLMUnavailable) as exc:
        gen(StubClient(error=err)).generate("s", "u")
    assert str(exc.value) == f"bedrock:{code}"  # the code only, never the message


def test_network_errors_become_llm_unavailable():
    with pytest.raises(LLMUnavailable):
        gen(StubClient(error=ConnectTimeoutError(endpoint_url="https://bedrock-runtime.example"))).generate("s", "u")


@pytest.mark.parametrize("bad", [{}, {"output": {}}, {"output": {"message": {"content": None}}}])
def test_malformed_responses_become_llm_unavailable(bad):
    with pytest.raises(LLMUnavailable):
        gen(StubClient(bad)).generate("s", "u")


def test_build_generator_respects_provider_setting():
    assert build_generator(Settings(llm_provider="disabled")) is None
    live = build_generator(Settings(llm_provider="bedrock", bedrock_model_id="some-model", aws_region="us-west-2"))
    assert live.model_id == "some-model"  # constructing the boto3 client makes no network call


def test_config_fails_fast_on_bad_llm_settings():
    with pytest.raises(ValidationError):
        Settings(llm_provider="bedrock")  # no model id
    with pytest.raises(ValidationError):
        Settings(llm_provider="openai")
