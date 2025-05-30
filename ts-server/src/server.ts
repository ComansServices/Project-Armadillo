import express from 'express';
import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import crypto from 'crypto';
import { exec } from 'child_process';
import { parseStringPromise } from 'xml2js';
import path from 'path';

const app = express();
app.use(express.json());

const XML_DIR = '/opt/xml';
const NOTES_DIR = '/opt/notes';

function tokenCheck(token: string): boolean {
  try {
    const tokenHash = fs.readFileSync('/root/token.sha256', 'utf8').trim();
    const provided = crypto.createHash('sha256').update(token).digest('hex');
    return provided === tokenHash;
  } catch {
    return false;
  }
}

function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.headers['x-auth-token'];
  if (typeof token === 'string' && tokenCheck(token)) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// List available scan XML files
app.get('/api/scans', authMiddleware, (req: Request, res: Response) => {
  try {
    const files = fs.readdirSync(XML_DIR).filter(f => f.endsWith('.xml'));
    return res.json({ files });
  } catch (err) {
    return res.status(500).json({ error: 'Unable to list scans' });
  }
});

// Get host details from a scan
app.get('/api/scan/:file/host/:address', authMiddleware, async (req: Request, res: Response) => {
  const file = path.basename(req.params.file);
  const address = req.params.address;
  try {
    const xmlPath = path.join(XML_DIR, file);
    const xmlData = fs.readFileSync(xmlPath, 'utf8');
    const parsed = await parseStringPromise(xmlData);
    const hosts = parsed.nmaprun.host;
    for (const host of hosts) {
      const addr = host.address?.['$']?.addr;
      if (addr === address) {
        return res.json({ host });
      }
    }
    return res.status(404).json({ error: 'Host not found' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to parse scan' });
  }
});

// Start a new scan
app.post('/api/scan', authMiddleware, (req: Request, res: Response) => {
  const { filename, target, params } = req.body;
  if (!/^[\w.-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const cmd = `nmap ${params} -oX ${path.join(XML_DIR, filename)} ${target}`;
  exec(cmd, err => {
    if (err) {
      return res.status(500).json({ error: 'nmap failed' });
    }
    return res.json({ ok: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
