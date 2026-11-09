const net = require('node:net');
const path = require('node:path');
const maxmind = require('maxmind');

const privateIpRanges = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
].forEach(([address, prefix]) => privateIpRanges.addSubnet(address, prefix, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001::', 23],
  ['2001:db8::', 32], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]
].forEach(([address, prefix]) => privateIpRanges.addSubnet(address, prefix, 'ipv6'));

const databaseReaders = new Map();

function getPublicClientIp(value) {
  if (typeof value !== 'string') return '';
  let address = value.trim().replace(/^\[|\]$/g, '').split('%')[0];
  const mappedIpv4 = address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mappedIpv4) address = mappedIpv4[1];
  const family = net.isIP(address);
  if (!family || privateIpRanges.check(address, family === 4 ? 'ipv4' : 'ipv6')) return '';
  return address;
}

function buildLoginNetworkDetails(clientIp, cityRecord, asnRecord) {
  return {
    client_ip: clientIp,
    country_code: cityRecord?.country?.iso_code || asnRecord?.country?.iso_code || '',
    city: cityRecord?.city?.names?.en || '',
    isp_provider: asnRecord?.autonomous_system_organization || ''
  };
}

function getDatabaseReader(configuredPath, type) {
  if (typeof configuredPath !== 'string' || !configuredPath.trim()) return Promise.resolve(null);
  const filePath = path.resolve(__dirname, configuredPath);
  const key = `${type}:${filePath}`;
  if (!databaseReaders.has(key)) {
    databaseReaders.set(key, maxmind.open(filePath).catch((error) => {
      console.error(`Could not open the configured GeoIP ${type} database:`, error);
      return null;
    }));
  }
  return databaseReaders.get(key);
}

async function resolveLoginNetwork(ip, {
  cityDatabasePath = process.env.GEOIP_CITY_DATABASE_PATH,
  asnDatabasePath = process.env.GEOIP_ASN_DATABASE_PATH
} = {}) {
  const clientIp = getPublicClientIp(ip);
  if (!clientIp) return buildLoginNetworkDetails('', null, null);

  const [cityDatabase, asnDatabase] = await Promise.all([
    getDatabaseReader(cityDatabasePath, 'city'),
    getDatabaseReader(asnDatabasePath, 'ASN')
  ]);
  let cityRecord = null;
  let asnRecord = null;
  try {
    cityRecord = cityDatabase?.get(clientIp) || null;
  } catch (error) {
    console.error('Could not look up login location:', error);
  }
  try {
    asnRecord = asnDatabase?.get(clientIp) || null;
  } catch (error) {
    console.error('Could not look up login network provider:', error);
  }
  return buildLoginNetworkDetails(clientIp, cityRecord, asnRecord);
}

module.exports = { buildLoginNetworkDetails, getPublicClientIp, resolveLoginNetwork };
