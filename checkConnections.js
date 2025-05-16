import child from 'child_process';
import psList from 'ps-list';
import axios from 'axios';
import { promisify } from 'util';

const execAsync = promisify(child.exec);

const VIRUSTOTAL_API_KEY = ''; //change virustotal key 

const isIPv4 = (ip) => /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(ip);
const isIPv6 = (ip) => /^([\da-f]{1,4}:){1,7}[\da-f]{1,4}(:\d+)?$/.test(ip);

async function checkIPWithVirusTotal(ip) {
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });

        const stats = response.data.data.attributes.last_analysis_stats;
        const isMalicious = stats.malicious > 0;

        return { isMalicious, stats };
    } catch (err) {
        console.error(`🔌 Error querying VirusTotal for IP ${ip}: ${err.message}`);
        return { isMalicious: false, stats: null };
    }
}

async function analyzeConnections() {
    try {
        const { stdout } = await execAsync('netstat -ano');

        const lines = stdout.split('\n');
        const connections = [];

        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 5) {
                const [protocol, localAddress, foreignAddress, state, pidStr] = parts.slice(0, 5);
                const pid = Number(pidStr);
                const ip = foreignAddress.split(':')[0];

                if (
                    (isIPv4(foreignAddress) || isIPv6(foreignAddress)) &&
                    pid > 0 &&
                    !ip.startsWith("127.") &&
                    !ip.startsWith("0.0.0.0")
                ) {
                    connections.push({ protocol, localAddress, foreignAddress, state, pid });
                }
            }
        }

        const processes = await psList();

        const enrichedConnections = await Promise.all(
            connections.map(async (conn) => {
                try {
                    const { stdout } = await execAsync(
                        `powershell -Command "Get-Process -Id ${conn.pid} | Select-Object -ExpandProperty Path"`
                    );
                    const processPath = stdout.trim();
                    const process = processes.find((p) => p.pid === conn.pid);

                    return {
                        ...conn,
                        processName: process ? process.name : 'Unknown',
                        processPath: processPath || 'Unavailable',
                    };
                } catch {
                    return {
                        ...conn,
                        processName: 'Unknown',
                        processPath: 'Unavailable',
                    };
                }
            })
        );

        for (const conn of enrichedConnections) {
            const ip = conn.foreignAddress.split(':')[0];
            const { isMalicious, stats } = await checkIPWithVirusTotal(ip);

            if (isMalicious) {
                console.warn(`⚠️ Malicious IP detected: ${ip}`);
                console.table({
                    ...conn,
                    VirusTotal: `Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}`,
                });
            } else {
                console.log(`✅ Clean IP: ${ip}`);
                console.table(conn);
            }
        }

    } catch (err) {
        console.error(`❌ Unexpected error: ${err.message}`);
    }
}

analyzeConnections();
