import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createBareServer } from "@nebula-services/bare-server-node";
import chalk from "chalk";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import basicAuth from "express-basic-auth";
import mime from "mime";
import fetch from "node-fetch";
import config from "./config.js";

const __dirname = path.dirname(new URL(import.meta.url).pathname);

console.log(chalk.yellow("🚀 Starting server..."));

let blockedSites = JSON.parse(fs.readFileSync(path.join(__dirname, 'blocklist.json')));

fs.watchFile(path.join(__dirname, 'blocklist.json'), () => {
  console.log("🔄 Blocklist updated");
  blockedSites = JSON.parse(fs.readFileSync(path.join(__dirname, 'blocklist.json')));
});

const server = http.createServer();
const app = express();
const bareServer = createBareServer("/ca/");
const PORT = process.env.PORT || 8080;
const cache = new Map();
const CACHE_TTL = 30 * 24 * 60 * 60 * 1000; // Cache for 30 Days

// 👥 Track active sessions (user -> IP)
const activeSessions = new Map();

// 🔐 Basic Auth
if (config.challenge !== false) {
  console.log(chalk.green("🔒 Password protection is enabled! Listing logins below"));
  Object.entries(config.users).forEach(([username, password]) => {
    console.log(chalk.blue(`Username: ${username}, Password: ${password}`));
  });

  app.use(basicAuth({ users: config.users, challenge: true }));

  // 🚫 Single Session Check
  app.use((req, res, next) => {
    const user = req.auth?.user;
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

    if (user) {
      const currentIP = activeSessions.get(user);
      if (currentIP && currentIP !== ip) {
        console.log(`🚫 ${user} already logged in from ${currentIP}, blocked ${ip}`);
        return res.status(403).send("Access denied: Account already in use.");
      }

      activeSessions.set(user, ip);
    }

    next();
  });
}

// 🚫 Banned IPs
const bannedIPs = [
  "203.0.113.42",
  "124.150.162.86"
];

app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (bannedIPs.includes(ip)) {
    console.log(`🚫 Blocked IP: ${ip}`);
    return res.status(403).send("Access denied.");
  }
  next();
});

// 🎮 Asset Proxy
app.get("/e/*", async (req, res, next) => {
  try {
    if (cache.has(req.path)) {
      const { data, contentType, timestamp } = cache.get(req.path);
      if (Date.now() - timestamp > CACHE_TTL) {
        cache.delete(req.path);
      } else {
        res.writeHead(200, { "Content-Type": contentType });
        return res.end(data);
      }
    }

    const baseUrls = {
      "/e/1/": "https://raw.githubusercontent.com/qrs/x/fixy/",
      "/e/2/": "https://raw.githubusercontent.com/3v1/V5-Assets/main/",
      "/e/3/": "https://raw.githubusercontent.com/3v1/V5-Retro/master/",
    };

    let reqTarget;
    for (const [prefix, baseUrl] of Object.entries(baseUrls)) {
      if (req.path.startsWith(prefix)) {
        reqTarget = baseUrl + req.path.slice(prefix.length);
        break;
      }
    }

    if (!reqTarget) return next();

    const asset = await fetch(reqTarget);
    if (!asset.ok) return next();

    const data = Buffer.from(await asset.arrayBuffer());
    const ext = path.extname(reqTarget);
    const no = [".unityweb"];
    const contentType = no.includes(ext)
      ? "application/octet-stream"
      : mime.getType(ext);

    cache.set(req.path, { data, contentType, timestamp: Date.now() });
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  } catch (error) {
    console.error("Error fetching asset:", error);
    res.setHeader("Content-Type", "text/html");
    res.status(500).send("Error fetching the asset");
  }
});

// 🧱 Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🚫 Blocklist Check
app.use((req, res, next) => {
  const target = req.query.url || req.body?.url || req.originalUrl;
  if (target) {
    const normalizedTarget = target.toLowerCase();
    if (blockedSites.some(site => normalizedTarget.includes(site.replace(/\/$/, '').toLowerCase()))) {
      console.log(`🚫 Blocked attempt: ${normalizedTarget}`);
      return res.status(403).send("🚫 This site is blocked.");
    }
  }
  next();
});

// 🧱 Static + Routes
app.use(express.static(path.join(__dirname, "static")));
app.use("/ca", cors({ origin: true }));

const routes = [
  { path: "/b", file: "apps.html" },
  { path: "/a", file: "games.html" },
  { path: "/play.html", file: "games.html" },
  { path: "/c", file: "settings.html" },
  { path: "/d", file: "tabs.html" },
  { path: "/", file: "index.html" },
];

routes.forEach(route => {
  app.get(route.path, (_req, res) => {
    res.sendFile(path.join(__dirname, "static", route.file));
  });
});

// 🧱 404 + Error
app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, "static", "404.html"));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).sendFile(path.join(__dirname, "static", "404.html"));
});

// 🔐 Enhanced blocklist logic
server.on("request", (req, res) => {
  const headers = req.headers;
  const hostHeader = headers.host?.toLowerCase() || "";
  const refererHeader = headers.referer?.toLowerCase() || "";
  const fullTarget = `${req.url} ${hostHeader} ${refererHeader}`;

  if (
    blockedSites.some(site =>
      fullTarget.includes(site.replace(/\/$/, '').toLowerCase())
    )
  ) {
    console.log(`🚫 Blocked attempt: ${fullTarget}`);
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("🚫 This site is blocked.");
  }

  if (bareServer.shouldRoute(req)) {
    bareServer.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

server.on("upgrade", (req, socket, head) => {
  if (bareServer.shouldRoute(req)) {
    bareServer.routeUpgrade(req, socket, head);
  } else {
    socket.end();
  }
});

server.on("listening", () => {
  console.log(chalk.green(`🌍 Server is running on http://localhost:${PORT}`));
});

server.listen({ port: PORT });
