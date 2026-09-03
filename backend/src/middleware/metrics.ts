/**
 * HTTP Request Metrics Middleware
 *
 * Records request count, latency histogram, and body size for every HTTP request.
 */

import type { Request, Response, NextFunction } from "express";
import {
  httpRequestsTotal,
  httpRequestDuration,
  httpRequestSize,
  httpResponseSize,
} from "../services/metrics.js";
import { normalizeRoute } from "../services/metrics.js";

/**
 * Express middleware that records Prometheus metrics for every request.
 *
 * Bug fix: the original version referenced `route` before it was defined when
 * observing `httpRequestSize`. Request body size is measured on the way in
 * using `req.path` (the best label we have before the router resolves
 * `req.route.path`). Response-side metrics continue to use the resolved route
 * from `req.route.path` on the `finish` event, giving low-cardinality labels.
 */
export function metricsMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const start = process.hrtime.bigint();
  const method = req.method;
  let recorded = false;

  // Track request body size on the way in.
  // At this point `req.route` is not yet populated, so we normalise req.path.
  // This is intentionally separate from the finish-event route label so that
  // the observation is not lost for requests that never complete normally.
  const contentLength = parseInt(req.headers["content-length"] || "0", 10);
  if (contentLength > 0) {
    const inboundRoute = normalizeRoute(req.path);
    httpRequestSize.observe({ method, route: inboundRoute }, contentLength);
  }

  // `finish` is emitted for all normal Express responses, including routes
  // that end through send/json rather than calling res.end directly. At this
  // point Express has resolved req.route, so route labels stay low-cardinality.
  res.once("finish", () => {
    if (recorded) return;
    recorded = true;
    const duration = Number(process.hrtime.bigint() - start) / 1e9;
    const route = normalizeRoute(
      typeof req.route?.path === "string" ? req.route.path : req.path,
    );
    const status = String(res.statusCode);

    httpRequestsTotal.inc({ method, route, status });
    httpRequestDuration.observe({ method, route, status }, duration);

    const resContentLength = Number(res.getHeader("content-length") || 0);
    if (Number.isFinite(resContentLength) && resContentLength > 0) {
      httpResponseSize.observe({ method, route, status }, resContentLength);
    }
  });

  next();
}
