import passport from "passport";

// utils/auth.js
export function getCurrentUser(req) {
    return req.user || null;
  }
  
  // Middleware: ensure the request is authenticated
export function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}