# Nmap Dashboard TypeScript Server

This folder contains a simple Express-based server that provides
API endpoints similar to the original Django application.

## Setup

1. Install dependencies:
   ```sh
   npm install
   ```
2. Build the project:
   ```sh
   npm run build
   ```
3. Run the server:
   ```sh
   npm start
   ```

During development you can run `npm run dev` if you have
`ts-node` installed.

The server reads scan files from `/opt/xml` and uses `/root/token.sha256`
for token authentication (send the token in the `X-Auth-Token` header).
