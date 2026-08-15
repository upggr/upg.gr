/** Retail products, translated inline since there are only a couple. */
export const products = [
  {
    id: 'smart-plug-16a',
    ean: '0653753598333',
    price: '€15',
    image: '/products/smart-plug.webp',
    el: {
      name: 'Έξυπνη Πρίζα WiFi 16A',
      lead:
        'Επαναπροσδιορίστε την άνεση στο σπίτι σας. Ιδανική για οικιακή ή γενική χρήση, συνδυάζει λειτουργικότητα, ασφάλεια και ευκολία, με παρακολούθηση κατανάλωσης σε πραγματικό χρόνο.',
      specs: [
        'WiFi 2.4GHz, πρότυπα IEEE 802.11 b/g/n',
        'Ονομαστική τάση AC 100–240V, 50/60Hz — μοντέλο 16A',
        'Παρακολούθηση κατανάλωσης σε πραγματικό χρόνο μέσω Tuya ή Smart Life',
        'Εντοπισμός ενεργοβόρων συσκευών και μείωση κόστους',
        'Διαστάσεις 84 × 50 × 50 mm — δεν μπλοκάρει τις διπλανές πρίζες',
        'Συμβατή με κάθε πρίζα ΕΕ',
      ],
    },
    en: {
      name: 'WiFi Smart Plug 16A',
      lead:
        'Rethink comfort at home. Suitable for domestic or general use, it combines functionality, safety and convenience, with real-time energy monitoring.',
      specs: [
        'WiFi 2.4GHz, IEEE 802.11 b/g/n compliant',
        'Rated AC 100–240V, 50/60Hz — 16A model',
        'Real-time power monitoring via Tuya or Smart Life',
        'Spot power-hungry appliances and cut running costs',
        'Compact 84 × 50 × 50 mm — never blocks the neighbouring socket',
        'Fits any EU socket',
      ],
    },
  },
  {
    id: 'temp-humidity-sensor',
    ean: '0653753598340',
    price: '€15',
    image: '/products/sensor.webp',
    el: {
      name: 'Αδιάβροχος Αισθητήρας Θερμοκρασίας & Υγρασίας WiFi',
      lead:
        'Ελέγξτε και παρακολουθήστε εύκολα το περιβάλλον σας. Ιδανικός για σπίτια, ξενοδοχεία και επαγγελματικούς χώρους, με υποστήριξη φωνητικού ελέγχου.',
      specs: [
        'Σύνδεση WiFi και απομακρυσμένος έλεγχος με Tuya Smart ή Smart Life',
        'Φωνητικός έλεγχος μέσω Amazon Alexa και Google Assistant',
        'Υποστηρίζει °C/°F και μορφή ώρας 12/24',
        'Λειτουργία από −10 °C έως 55 °C και υγρασία 10–90% RH',
        'Μπαταρία διάρκειας 6–8 μηνών με υπενθύμιση χαμηλής στάθμης',
        'Διαστάσεις 7.5 × 2.8 × 2.5 cm — βάρος μόλις 30 g',
      ],
    },
    en: {
      name: 'Waterproof WiFi Temperature & Humidity Sensor',
      lead:
        'Monitor and control your environment with ease. Ideal for homes, hotels and workplaces, with voice assistant support.',
      specs: [
        'WiFi connectivity and remote control via Tuya Smart or Smart Life',
        'Voice control through Amazon Alexa and Google Assistant',
        'Supports °C/°F and 12/24-hour time formats',
        'Operates from −10 °C to 55 °C and 10–90% RH',
        'Battery lasts 6–8 months with a low-battery reminder',
        'Compact 7.5 × 2.8 × 2.5 cm — just 30 g',
      ],
    },
  },
] as const;
