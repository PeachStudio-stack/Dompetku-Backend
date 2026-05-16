module.exports = {
  apps: [
    {
      name: "Dompetku-BackendOnly",
      script: "server.js",
      cwd: "/var/www/BackendOnly",
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      max_memory_restart: "300M",
      env: {
        NODE_ENV: "production",
        PORT: 3000
      }
    }
  ]
};
