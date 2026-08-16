export const site = {
  name: 'UPGRADE',
  legalName: 'UPGRADE — Buy IT',
  url: 'https://upg.gr',
  email: 'help@upg.gr',
  phones: [
    { display: '+30 26951 95642', href: '+302695195642' },
    { display: '+30 698 810 4870', href: '+306988104870' },
  ],
  sister: { name: 'Buy IT', url: 'https://buy-it.gr' },
  social: [
    { name: 'Facebook', href: 'https://www.facebook.com/d3scr1pt0r' },
    { name: 'Instagram', href: 'https://www.instagram.com/upggr/' },
    { name: 'X', href: 'https://x.com/d3scr1pt0r' },
  ],
  offices: [
    {
      id: 'zakynthos',
      lat: 37.78582667198258,
      lng: 20.89434907657635,
      maps: 'https://www.google.com/maps/search/?api=1&query=37.78582667198258,20.89434907657635',
      embed:
        'https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3153.179766434212!2d20.89434907657635!3d37.78582667198258!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x1367475801c49bbf%3A0x3a8bf29aad030581!2sUPGRADE!5e0!3m2!1sen!2sgr!4v1729595161290!5m2!1sen!2sgr',
    },
    {
      id: 'tragaki',
      lat: 37.823468882366186,
      lng: 20.847967691366634,
      maps: 'https://www.google.com/maps/search/?api=1&query=37.823468882366186,20.847967691366634',
      embed:
        'https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3151.573026340621!2d20.847967691366634!3d37.823468882366186!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x136747acbb0b7073%3A0x4fc2505f32a0be32!2sBuy%20IT!5e0!3m2!1sen!2sgr!4v1729595293011!5m2!1sen!2sgr',
    },
  ],
} as const;

/** Client names are proper nouns — shown as-is in both languages. */
export const clients = {
  web: [
    'Laura Suites', 'Alisaxni', "Anna's Kitchen", 'Artogonia', 'Auto Traffic Rentals',
    'Avesta Private Villas', 'Cameo Beach Resort', 'Diana Palace Hotel', 'Diana Hotel',
    'Meandros Boutique Hotel', 'Filoxenia Hotel', 'Equidata Solutions', 'La Femme Spa',
    'History War Museum', 'Good Times Photography', 'Νώε Beach Club', "Nonna's Kitchen Bar",
    'Physiotherapy Zakynthos', 'San Antonio Villas', 'The Impartial Press',
    'Theodoros Kolpondinos', 'Traventure', 'Villa Sunshine', 'Villa Romano', 'Zante Work',
    'Xenos Hotels', 'Artina Villa', 'Aeonian Spa', 'Fidelity Travel', 'Routelab',
    'Entipo', 'Istros', 'Home Mobile', 'ZanteWize',
  ],
  infra: [
    'Γενικό Νοσοκομείο Ζακύνθου', 'Δημόσια Ιστορική Βιβλιοθήκη Ζακύνθου', 'Κλινική Γαλληνός',
    'Iassis Medical', 'Health Direct', 'My Body Clinic', 'My Face Clinic', 'My Hair Greece',
    'My Laser Clinic', 'Met Cosmetic', 'Patra Laser', 'Patra Men Cosmetic', 'I Assist',
    'I Assist Patra', 'Doctor Greece', 'Alpha Health', 'Eternal Life', 'Καντίνες Σκρέτας',
  ],
  security: [
    'Cameo Beach Resort', 'Diana Palace Hotel', 'Xenos Hotels', 'Κλινική Γαλληνός',
    'Iassis Medical', 'Equidata Solutions', 'Met Cosmetic Shop', 'My Rapid Test',
  ],
  telephony: ['Xenos Hotels', 'Cameo Beach Resort', 'Health Direct', 'I Assist'],
  iptv: [
    'Ionian TV — IPTV streaming infrastructure',
    'Ερμής Radio — icecast streaming',
    'Μητρόπολη Ζακύνθου — icecast streaming',
    'Greek TV',
    'Ionian TV App',
  ],
} as const;

export type ClientCategory = keyof typeof clients;
