const NAMIBIAN_TOWNS = Object.freeze(require('../client/namibian-towns.json'));

function normalizeNamibianTown(value, towns = NAMIBIAN_TOWNS) {
  if (typeof value !== 'string') return '';
  const town = value.normalize('NFKC').trim().replace(/\s+/g, ' ');
  if (!town || town.length > 80 || !/^[\p{L}\p{M}][\p{L}\p{M} .'-]{0,79}$/u.test(town)) return '';

  const knownTown = towns.find((known) => known.toLocaleLowerCase('en') === town.toLocaleLowerCase('en'));
  if (knownTown) return knownTown;

  return town.toLocaleLowerCase('en')
    .replace(/(^|[\s'-])([\p{L}\p{M}])/gu, (_match, separator, letter) => `${separator}${letter.toLocaleUpperCase('en')}`);
}

module.exports = { NAMIBIAN_TOWNS, normalizeNamibianTown };
