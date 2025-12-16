const request = require("supertest");
const app = require("../app");

describe("Register validation", () => {
  it("should fail without email/password", async () => {
    const res = await request(app).post("/register").send({});
    expect(res.statusCode).toBe(400);
  });
});
