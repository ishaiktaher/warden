from __future__ import annotations

import unittest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from control_plane.observability import RequestBodyLimitMiddleware


class RequestBodyLimitTests(unittest.TestCase):
    def test_content_length_over_limit_is_rejected_before_route(self) -> None:
        app = FastAPI()
        app.add_middleware(RequestBodyLimitMiddleware, max_bytes=32)

        @app.post("/")
        async def receive(request: Request) -> dict:
            return {"size": len(await request.body())}

        response = TestClient(app).post("/", content=b"x" * 33)
        self.assertEqual(413, response.status_code)
        self.assertIn("configured limit", response.json()["error"]["detail"])
        self.assertEqual("invalid_request", response.json()["error"]["code"])


if __name__ == "__main__":
    unittest.main()
