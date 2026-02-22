from libproxy import Message
import pytest


def test_create_reply():
    message = Message(None, None, None, None, None, None, None)
    message.reply_headers = {
        "Proto": "HTTP/1.1",
        "Code": "200",
        "Message": "OK",
        "Content-Type": "application/json",
        "Date": "Sat, 21 Feb 2026 14:41:16 GMT",
        "Content-Length": "925",
    }
    message.reply_body = [
        {
            "id": "3593922b-e906-430e-ab9a-18b1e0e7dbe0",
            "created_at": "2026-01-26 07:22:30.454619 +0000 +0000",
            "updated_at": "2026-01-26 07:22:30.454619 +0000 +0000",
            "body": "I'm the one who knocks!",
            "user_id": "4e9fab33-0880-4d2c-a1cd-89586111b71f",
        },
        {
            "id": "e552de25-3198-41a5-9d2c-21db4ca06514",
            "created_at": "2026-01-26 07:22:30.483599 +0000 +0000",
            "updated_at": "2026-01-26 07:22:30.483599 +0000 +0000",
            "body": "Gale!",
            "user_id": "4e9fab33-0880-4d2c-a1cd-89586111b71f",
        },
        {
            "id": "6e0460e4-f31c-457f-b60a-f361574ea178",
            "created_at": "2026-01-26 07:22:30.485478 +0000 +0000",
            "updated_at": "2026-01-26 07:22:30.485478 +0000 +0000",
            "body": "Cmon Pinkman",
            "user_id": "4e9fab33-0880-4d2c-a1cd-89586111b71f",
        },
        {
            "id": "eb74fe38-55d6-41f1-ab1d-a279d963b829",
            "created_at": "2026-01-26 07:22:30.487267 +0000 +0000",
            "updated_at": "2026-01-26 07:22:30.487267 +0000 +0000",
            "body": "Darn that fly, I just wanna cook",
            "user_id": "4e9fab33-0880-4d2c-a1cd-89586111b71f",
        },
    ]
    expected_content = b'HTTP/1.1 200 OK\r\nContent-Type:application/json\r\nDate:Sat, 21 Feb 2026 14:41:16 GMT\r\nContent-Length:925\r\n\r\n[{"id":"3593922b-e906-430e-ab9a-18b1e0e7dbe0","created_at":"2026-01-26 07:22:30.454619 +0000 +0000","updated_at":"2026-01-26 07:22:30.454619 +0000 +0000","body":"I\'m the one who knocks!","user_id":"4e9fab33-0880-4d2c-a1cd-89586111b71f"},{"id":"e552de25-3198-41a5-9d2c-21db4ca06514","created_at":"2026-01-26 07:22:30.483599 +0000 +0000","updated_at":"2026-01-26 07:22:30.483599 +0000 +0000","body":"Gale!","user_id":"4e9fab33-0880-4d2c-a1cd-89586111b71f"},{"id":"6e0460e4-f31c-457f-b60a-f361574ea178","created_at":"2026-01-26 07:22:30.485478 +0000 +0000","updated_at":"2026-01-26 07:22:30.485478 +0000 +0000","body":"Cmon Pinkman","user_id":"4e9fab33-0880-4d2c-a1cd-89586111b71f"},{"id":"eb74fe38-55d6-41f1-ab1d-a279d963b829","created_at":"2026-01-26 07:22:30.487267 +0000 +0000","updated_at":"2026-01-26 07:22:30.487267 +0000 +0000","body":"Darn that fly, I just wanna cook","user_id":"4e9fab33-0880-4d2c-a1cd-89586111b71f"}]'
    message._serialize_resp()
    print(f"out {message.c_outb}")
    print(f"exp {expected_content}")
    assert message.c_outb == expected_content
