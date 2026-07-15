import json


async def test_hello(jp_fetch):
    # When
    response = await jp_fetch("jupyterlab-passkey-extension", "hello")

    # Then
    assert response.code == 200
    payload = json.loads(response.body)
    assert payload == {
            "data": (
                "Hello, world!"
                " This is the '/jupyterlab-passkey-extension/hello' endpoint."
                " Try visiting me in your browser!"
            ),
        }
