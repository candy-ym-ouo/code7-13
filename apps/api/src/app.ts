import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import { config } from "./config";
import { AppError } from "./errors";
import { query } from "./db";
import { authRoutes } from "./routes/auth";
import { featureRoutes } from "./routes/features";
import { mediaRoutes } from "./routes/media";
import { commentRoutes } from "./routes/comments";
import { reportRoutes } from "./routes/reports";
import { moderationRoutes } from "./routes/moderation";
import { forensicsRoutes } from "./routes/forensics";

export async function buildApp() {
  const app = Fastify({
    logger: {
      level: config.NODE_ENV === "production" ? "info" : "debug",
      redact: ["req.headers.authorization", "req.headers.cookie", "res.headers.set-cookie"]
    },
    trustProxy: true,
    bodyLimit: 1024 * 1024
  });

  await app.register(cookie);
  await app.register(cors, {
    origin: config.APP_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "Idempotency-Key"]
  });
  await app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: "1 minute"
  });

  app.addHook("onSend", async (_request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "strict-origin-when-cross-origin");
    reply.header("Permissions-Policy", "geolocation=(self)");
  });

  app.get("/health/live", async () => ({ status: "ok" }));
  app.get("/health/ready", async (_request, reply) => {
    try {
      await query("SELECT 1");
      return { status: "ready" };
    } catch {
      return reply.code(503).send({ status: "not_ready" });
    }
  });

  await app.register(async (api) => {
    api.register(authRoutes);
    api.register(featureRoutes);
    api.register(mediaRoutes);
    api.register(commentRoutes);
    api.register(reportRoutes);
    api.register(moderationRoutes);
    api.register(forensicsRoutes);
  }, { prefix: "/api/v1" });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ZodError) {
      return reply.code(400).send({
        type: "about:blank",
        title: "Validation failed",
        status: 400,
        code: "VALIDATION_FAILED",
        detail: "Request did not match the required schema",
        issues: error.issues,
        requestId: request.id
      });
    }
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send({
        type: "about:blank",
        title: error.code,
        status: error.statusCode,
        code: error.code,
        detail: error.message,
        details: error.details,
        requestId: request.id
      });
    }
    request.log.error({ err: error }, "unhandled request error");
    return reply.code(500).send({
      type: "about:blank",
      title: "INTERNAL_ERROR",
      status: 500,
      code: "INTERNAL_ERROR",
      detail: "An unexpected error occurred",
      requestId: request.id
    });
  });

  app.setNotFoundHandler((request, reply) => reply.code(404).send({
    type: "about:blank",
    title: "NOT_FOUND",
    status: 404,
    code: "NOT_FOUND",
    detail: "Route not found",
    requestId: request.id
  }));

  return app;
}
