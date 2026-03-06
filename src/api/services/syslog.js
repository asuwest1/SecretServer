import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';

export class SyslogService {
  constructor(config, logger, dependencies = {}) {
    this.config = config;
    this.logger = logger;
    this.netModule = dependencies.netModule || net;
    this.dgramModule = dependencies.dgramModule || dgram;
    this.tlsModule = dependencies.tlsModule || tls;
  }

  send(entry) {
    if (!this.config.enabled) {
      return;
    }

    const message = `<134>1 ${new Date().toISOString()} secret-server - ${entry.action || 'EVENT'} - [meta user=\"${entry.username || 'system'}\" resource_id=\"${entry.resourceId || '-'}\"] ${entry.action || 'event'}`;
    const protocol = (this.config.protocol || '').toLowerCase();

    if (protocol === 'tls' || (protocol === 'tcp' && this.config.tlsEnabled)) {
      const socket = this.tlsModule.connect({
        host: this.config.server,
        port: this.config.port,
        rejectUnauthorized: this.config.tlsRejectUnauthorized !== false,
      });
      socket.on('secureConnect', () => {
        socket.write(`${message}\n`);
        socket.end();
      });
      socket.on('error', (err) => this.logger.warn('syslog_tls_failed', { error: err.message }));
      return;
    }

    if (protocol === 'tcp') {
      const socket = this.netModule.createConnection(this.config.port, this.config.server);
      socket.on('connect', () => {
        socket.write(`${message}\n`);
        socket.end();
      });
      socket.on('error', (err) => this.logger.warn('syslog_tcp_failed', { error: err.message }));
      return;
    }

    if (protocol === 'udp' || !protocol) {
      const socket = this.dgramModule.createSocket('udp4');
      socket.send(Buffer.from(message), this.config.port, this.config.server, (err) => {
        if (err) {
          this.logger.warn('syslog_udp_failed', { error: err.message });
        }
        socket.close();
      });
      return;
    }

    this.logger.warn('syslog_protocol_invalid', { protocol });
  }
}
