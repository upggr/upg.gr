/** Software we build and run ourselves — offered to clients as part of a project. */
export const platforms = [
  {
    id: 'chronoticket',
    url: 'https://chronoticket.com',
    icon: 'ticket',
    el: {
      name: 'ChronoTicket',
      tag: 'Ticketing & υποστήριξη',
      text: 'Η δική μας πλατφόρμα ticketing. Multi-tenant, με SLA, χρεώσιμο χρόνο, συνημμένα και πλήρες ιστορικό ανά πελάτη — το ίδιο σύστημα με το οποίο σας υποστηρίζουμε.',
    },
    en: {
      name: 'ChronoTicket',
      tag: 'Ticketing & support desk',
      text: 'Our own ticketing platform. Multi-tenant, with SLAs, billable time, attachments and a full per-client history — the same system we support you through.',
    },
  },
  {
    id: 'static-forms',
    url: 'https://static-forms.com',
    icon: 'inbox',
    el: {
      name: 'StaticForms',
      tag: 'Φόρμες που φτάνουν πάντα',
      text: 'Backend φορμών για στατικά sites, χωρίς server. Παράδοση σε email, Telegram και webhooks, με φιλτράρισμα spam, αυτόματες απαντήσεις και ενιαίο dashboard υποβολών.',
    },
    en: {
      name: 'StaticForms',
      tag: 'Forms that always arrive',
      text: 'A form backend for static sites, with no server to run. Delivery over email, Telegram and webhooks, with spam filtering, auto-replies and one dashboard for every submission.',
    },
  },
  {
    id: 'kukibot',
    url: 'https://kukibot.com',
    icon: 'shield-check',
    el: {
      name: 'KukiBot',
      tag: 'Συναίνεση cookies & GDPR',
      text: 'Banner συναίνεσης cookies που μπλοκάρει τα trackers πριν φορτώσουν, όχι μετά. Ένα script tag, συμβατό με Astro, WordPress, Webflow ή απλό HTML, με καταγραφή συναινέσεων.',
    },
    en: {
      name: 'KukiBot',
      tag: 'Cookie consent & GDPR',
      text: 'A cookie consent banner that blocks trackers before they load, not after. One script tag, works with Astro, WordPress, Webflow or plain HTML, with a full consent record.',
    },
  },
] as const;
