/**
 * Recurring services we run for clients. Described by what they do, not by the
 * vendor behind them — the supplier can change without the offer changing.
 */
export const managedServices = [
  {
    id: 'email-delivery',
    icon: 'send',
    el: {
      name: '100% Παράδοση Email',
      text: 'Τα emails της ιστοσελίδας και του συστήματός σας φτάνουν πάντα — φόρμες, επιβεβαιώσεις κρατήσεων και τιμολόγια, με SPF/DKIM/DMARC και αναφορές παράδοσης.',
    },
    en: {
      name: '100% Email Delivery',
      text: 'Email from your site and systems always arrives — forms, booking confirmations and invoices, with SPF/DKIM/DMARC set up and delivery reporting.',
    },
  },
  {
    id: 'microsoft-365',
    icon: 'mail',
    el: {
      name: 'Microsoft 365',
      text: 'Επαγγελματικό email, Teams, SharePoint και OneDrive. Επίσημοι μεταπωλητές στις τιμές της Microsoft, με μετάβαση, διαχείριση χρηστών και υποστήριξη.',
    },
    en: {
      name: 'Microsoft 365',
      text: 'Business email, Teams, SharePoint and OneDrive. Official reseller at Microsoft list prices, with migration, user management and support.',
    },
  },
  {
    id: 'endpoint-protection',
    icon: 'shield',
    el: {
      name: 'Προστασία & Backup Συσκευών',
      text: 'Antivirus, EDR και προστασία από ransomware σε κάθε υπολογιστή και server, με απομακρυσμένη παρακολούθηση και backup στο cloud κάθε ώρα.',
    },
    en: {
      name: 'Endpoint Protection & Backup',
      text: 'Antivirus, EDR and ransomware protection on every desktop and server, with remote monitoring and hourly cloud backup.',
    },
  },
  {
    id: 'saas-backup',
    icon: 'archive',
    el: {
      name: 'Backup Microsoft 365',
      text: 'Το Microsoft 365 δεν κρατά δικά σας αντίγραφα. Κρατάμε emails, OneDrive και SharePoint σε ξεχωριστή υποδομή, με ανάκτηση από οποιαδήποτε ημερομηνία.',
    },
    en: {
      name: 'Microsoft 365 Backup',
      text: 'Microsoft 365 keeps no backup for you. We retain mail, OneDrive and SharePoint on separate infrastructure, restorable from any point in time.',
    },
  },
  {
    id: 'web-hosting',
    icon: 'globe',
    el: {
      name: 'Φιλοξενία & Domains',
      text: 'Γρήγορη φιλοξενία με CDN, πιστοποιητικά SSL, παρακολούθηση διαθεσιμότητας και πλήρη διαχείριση domain names.',
    },
    en: {
      name: 'Hosting & Domains',
      text: 'Fast CDN-backed hosting, SSL certificates, uptime monitoring and full domain name management.',
    },
  },
  {
    id: 'booking',
    icon: 'calendar',
    el: {
      name: 'Συστήματα Κρατήσεων',
      text: 'Online κρατήσεις και ραντεβού ενσωματωμένα στην ιστοσελίδα σας, με ημερολόγιο, υπενθυμίσεις και πληρωμές.',
    },
    en: {
      name: 'Booking Systems',
      text: 'Online bookings and appointments built into your site, with calendars, reminders and payments.',
    },
  },
  {
    id: 'cloud-servers',
    icon: 'server',
    el: {
      name: 'Cloud Servers',
      text: 'Ιδιωτικοί και dedicated servers για εφαρμογές, βάσεις δεδομένων και streaming, με παρακολούθηση και συντήρηση.',
    },
    en: {
      name: 'Cloud Servers',
      text: 'Private and dedicated servers for applications, databases and streaming, monitored and maintained by us.',
    },
  },
  {
    id: 'network',
    icon: 'wifi',
    el: {
      name: 'Δίκτυα & Firewall',
      text: 'Διαχειριζόμενα switches, WiFi για ξενοδοχεία, VLAN και next-generation firewall με φιλτράρισμα και VPN.',
    },
    en: {
      name: 'Networking & Firewall',
      text: 'Managed switches, hotel-grade WiFi, VLANs and next-generation firewalls with filtering and VPN.',
    },
  },
] as const;
