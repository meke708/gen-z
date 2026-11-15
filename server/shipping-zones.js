const townRegions = Object.freeze({
  Erongo: ['Arandis', 'Henties Bay', 'Karibib', 'Omaruru', 'Swakopmund', 'Uis', 'Usakos', 'Walvis Bay'],
  Hardap: ['Aranos', 'Gibeon', 'Gochas', 'Kalkrand', 'Maltahöhe', 'Mariental', 'Rehoboth', 'Stampriet'],
  Karas: ['Aroab', 'Aus', 'Aussenkehr', 'Bethanie', 'Berseba', 'Karasburg', 'Keetmanshoop', 'Lüderitz', 'Noordoewer', 'Oranjemund', 'Rosh Pinah', 'Tses'],
  KavangoEast: ['Divundu', 'Rundu'],
  KavangoWest: ['Nkurenkuru'],
  Khomas: ['Windhoek'],
  Kunene: ['Kamanjab', 'Khorixas', 'Opuwo', 'Outjo'],
  Ohangwena: ['Eenhana', 'Helao Nafidi', 'Okongo', 'Oshikango'],
  Omaheke: ['Gobabis', 'Leonardville', 'Otjinene'],
  Omusati: ['Okahao', 'Oshikuku', 'Outapi', 'Ruacana', 'Tsandi'],
  Oshana: ['Ondangwa', 'Ongwediva', 'Oshakati'],
  Oshikoto: ['Omuthiya', 'Tsumeb'],
  Otjozondjupa: ['Grootfontein', 'Okahandja', 'Okakarara', 'Otavi', 'Otjiwarongo'],
  Zambezi: ['Katima Mulilo', 'Kongola']
});
const regionByTown = new Map();

for (const [region, towns] of Object.entries(townRegions)) {
  for (const town of towns) regionByTown.set(town, region);
}

const hubTowns = new Set(['Windhoek', 'Swakopmund', 'Walvis Bay', 'Oshakati', 'Rundu', 'Otjiwarongo']);

function resolveShippingZone(sellerTown, deliveryTown) {
  if (sellerTown === deliveryTown) return 'local';
  const sellerRegion = regionByTown.get(sellerTown);
  if (sellerRegion && sellerRegion === regionByTown.get(deliveryTown)) return 'regional';
  if (hubTowns.has(sellerTown) && hubTowns.has(deliveryTown)) return 'hub';
  return 'remote';
}

module.exports = { resolveShippingZone };
