'use strict';

const PROTOCOL_PRESETS = [
  {
    id: 'http', name: 'HTTP', description: 'Web without TLS', rules: [{ proto: 'tcp', startPort: 80, endPort: 80 }],
  },
  {
    id: 'https', name: 'HTTPS / QUIC', description: 'TLS web traffic on standard ports', rules: [{ proto: 'tcp', startPort: 443, endPort: 443 }, { proto: 'udp', startPort: 443, endPort: 443 }],
  },
  {
    id: 'ssh-sftp', name: 'SSH / SFTP / SCP', description: 'Secure shell and file transfer', rules: [{ proto: 'tcp', startPort: 22, endPort: 22 }],
  },
  {
    id: 'ftp', name: 'FTP', description: 'FTP control and standard data ports', rules: [{ proto: 'tcp', startPort: 20, endPort: 21 }],
  },
  {
    id: 'dns', name: 'DNS', description: 'Domain name resolution', rules: [{ proto: 'tcp', startPort: 53, endPort: 53 }, { proto: 'udp', startPort: 53, endPort: 53 }],
  },
  {
    id: 'smtp', name: 'SMTP', description: 'Outgoing email', rules: [{ proto: 'tcp', startPort: 25, endPort: 25 }, { proto: 'tcp', startPort: 465, endPort: 465 }, { proto: 'tcp', startPort: 587, endPort: 587 }],
  },
  {
    id: 'imap', name: 'IMAP', description: 'Email retrieval', rules: [{ proto: 'tcp', startPort: 143, endPort: 143 }, { proto: 'tcp', startPort: 993, endPort: 993 }],
  },
  {
    id: 'pop3', name: 'POP3', description: 'Email retrieval', rules: [{ proto: 'tcp', startPort: 110, endPort: 110 }, { proto: 'tcp', startPort: 995, endPort: 995 }],
  },
  {
    id: 'telnet', name: 'Telnet', description: 'Unencrypted remote shell', rules: [{ proto: 'tcp', startPort: 23, endPort: 23 }],
  },
  {
    id: 'smb', name: 'SMB / CIFS', description: 'Windows file sharing', rules: [{ proto: 'udp', startPort: 137, endPort: 138 }, { proto: 'tcp', startPort: 139, endPort: 139 }, { proto: 'tcp', startPort: 445, endPort: 445 }],
  },
  {
    id: 'nfs', name: 'NFS', description: 'Network File System', rules: [{ proto: 'tcp', startPort: 2049, endPort: 2049 }, { proto: 'udp', startPort: 2049, endPort: 2049 }],
  },
  {
    id: 'rdp', name: 'RDP', description: 'Remote Desktop Protocol', rules: [{ proto: 'tcp', startPort: 3389, endPort: 3389 }, { proto: 'udp', startPort: 3389, endPort: 3389 }],
  },
  {
    id: 'mysql', name: 'MySQL / MariaDB', description: 'SQL database', rules: [{ proto: 'tcp', startPort: 3306, endPort: 3306 }],
  },
  {
    id: 'postgresql', name: 'PostgreSQL', description: 'SQL database', rules: [{ proto: 'tcp', startPort: 5432, endPort: 5432 }],
  },
  {
    id: 'redis', name: 'Redis', description: 'Redis database', rules: [{ proto: 'tcp', startPort: 6379, endPort: 6379 }],
  },
  {
    id: 'mongodb', name: 'MongoDB', description: 'MongoDB database', rules: [{ proto: 'tcp', startPort: 27017, endPort: 27017 }],
  },
  {
    id: 'mqtt', name: 'MQTT', description: 'MQTT messaging', rules: [{ proto: 'tcp', startPort: 1883, endPort: 1883 }, { proto: 'tcp', startPort: 8883, endPort: 8883 }],
  },
];

const PROTOCOL_PRESET_IDS = new Set(PROTOCOL_PRESETS.map(({ id }) => id));
const MAX_CUSTOM_RULES = 32;

const createDefaultNetworkPolicy = () => ({
  blockedProtocols: [],
  customRules: [],
  peerAllowlist: [],
});

const getProtocolPresets = () => PROTOCOL_PRESETS.map((preset) => ({
  ...preset,
  rules: preset.rules.map((rule) => ({ ...rule })),
}));

module.exports = {
  MAX_CUSTOM_RULES,
  PROTOCOL_PRESETS,
  PROTOCOL_PRESET_IDS,
  createDefaultNetworkPolicy,
  getProtocolPresets,
};
