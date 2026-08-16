export default {
  meta: {
    lang: 'en',
    dir: 'ltr',
    siteName: 'UPGRADE',
    home: {
      title: 'UPGRADE — Managed IT & Technology Support in Zakynthos',
      description:
        'Full-service IT in Zakynthos: 24/7 managed support, cybersecurity, backup & disaster recovery, Microsoft 365 and web hosting. ISO 9001 certified.',
    },
    security: {
      title: 'Cyber Security — A Practical Guide for Offices & Hotels | UPGRADE',
      description:
        'Practical cybersecurity guide: firewall sizing, antivirus/EDR, 3-2-1 backup, email and network security for businesses and hotels.',
    },
    products: {
      title: 'Smart Home & IoT Products | UPGRADE',
      description:
        'WiFi 16A smart plug and waterproof WiFi temperature & humidity sensor, with Tuya / Smart Life support.',
    },
    projects: {
      title: 'Projects & Clients | UPGRADE',
      description:
        'Selected projects and infrastructure we manage: web design, hosting, DNS, cybersecurity, Microsoft 365 and cloud.',
    },
    pricing: {
      title: 'Service Pricing | UPGRADE',
      description:
        'Transparent pricing: hourly support, per-device security packages, web hosting and Microsoft 365.',
    },
  },

  nav: {
    home: 'Home',
    services: 'Services',
    security: 'Cyber Security',
    products: 'Products',
    projects: 'Projects',
    pricing: 'Pricing',
    clients: 'Clients',
    team: 'Team',
    contact: 'Contact',
    menu: 'Menu',
    close: 'Close',
    openMenu: 'Open menu',
    skipToContent: 'Skip to content',
  },

  theme: {
    label: 'Theme',
    toggle: 'Toggle dark mode',
    light: 'Light',
    dark: 'Dark',
  },

  lang: {
    label: 'Language',
    switchTo: 'Αλλαγή στα Ελληνικά',
    el: 'Ελληνικά',
    en: 'English',
  },

  hero: {
    badge: 'ISO 9001 certified',
    title: 'Technology Support Services',
    lead:
      'Our company in Zakynthos delivers end-to-end IT services with a focus on security, reliability and speed. From design through implementation and maintenance, we build tailored solutions that match the way you actually work.',
    ctaPrimary: 'Get support now',
    ctaSecondary: 'See pricing',
    pillars: [
      { title: 'Lower Cost', text: 'Predictable monthly cost with no surprises.' },
      { title: '24/7 Support', text: 'We are available whenever you need us.' },
      { title: 'Clear Contracts', text: 'Transparent terms and hourly rates.' },
      { title: 'Security First', text: 'Data protection at every layer.' },
    ],
    stats: [
      { value: '65+', label: 'Business clients' },
      { value: '460+', label: 'Microsoft 365 seats' },
      { value: '430+', label: 'Protected devices' },
      { value: '24/7', label: 'Support' },
    ],
  },

  about: {
    eyebrow: 'Upgrade & Buy It',
    title: 'One point of support for your whole infrastructure',
    body: [
      'Our company in Zakynthos specialises in security services and backup and disaster recovery (BDR) solutions. We protect your data with advanced security systems and build dependable recovery plans, keeping your business running whatever happens.',
      'We also support your technology stack regardless of vendor, giving you a single point of contact backed by proper ticketing, documentation and response systems.',
    ],
  },

  services: {
    eyebrow: 'Services',
    title: 'Everything your business needs, from one team',
    lead:
      'We cover the full lifecycle of your technology — from planning and procurement through to day-to-day support and security.',
    items: [
      {
        title: 'Managed IT & Helpdesk',
        text: 'Remote and on-site support with ticketing, RMM monitoring and preventive maintenance.',
      },
      {
        title: 'Cybersecurity',
        text: 'Next-generation firewall, antivirus, EDR/XDR/MDR and email security built on Sophos and Datto.',
      },
      {
        title: 'Backup & Disaster Recovery',
        text: 'Hourly cloud backups, tested recovery plans and Microsoft 365 SaaS protection.',
      },
      {
        title: 'Networking & WiFi',
        text: 'Structured cabling, switching, VLANs, hotel-grade WiFi and WAN balancing over Starlink or OTE.',
      },
      {
        title: 'Microsoft 365 & Cloud',
        text: 'Official Microsoft reseller. Migration, user management, SharePoint/OneDrive and backup.',
      },
      {
        title: 'Web & Hosting',
        text: 'Website design, CDN-backed hosting, forms, email delivery and booking systems.',
      },
      {
        title: 'ERP & e-Invoicing',
        text: 'SoftOne and EpsilonNet solutions: ERP, Pylon, Epsilon Smart, Hotel/Rest and e-invoicing provider.',
      },
      {
        title: 'IPTV, Streaming & VoIP',
        text: 'IPTV and icecast streaming infrastructure, 3CX phone systems and hotel solutions.',
      },
    ],
  },

  managed: {
    eyebrow: 'Subscription services',
    title: 'Services we run for you',
    lead:
      'Services we provide and manage on an ongoing basis — one bill, one point of support, and no vendors for you to deal with.',
  },

  platforms: {
    eyebrow: 'Our own tools',
    title: 'Software we build and run ourselves',
    lead:
      'We do not only resell — we develop and maintain our own platforms. We use them every day to serve our clients, and they are available to you too.',
  },

  stack: {
    eyebrow: 'Software & Hardware Stack',
    title: 'Vendor agnostic by nature',
    lead: 'The tools and partners we build on.',
    tabs: {
      partners: 'Partners',
      distro: 'Distributors',
      web: 'Web Stack',
      infra: 'Infrastructure',
    },
    groups: {
      partners: [
        'Sophos — Firewall, Antivirus, Email Security',
        'Datto — RMM, Antivirus, BCDR, SaaS Protection',
        'Microsoft — Everything!',
        'Dell · HPe · Lenovo',
        'SoftOne · Impact · WebHotelier',
        'EpsilonNet',
      ],
      distro: ['NSS', 'Gerasis', 'InfoQuest', 'Logicom', 'Solidus', 'e-lenovo'],
      web: [
        'Hosting — Hetzner · AWS · Azure · Cloudflare',
        'Management — Runcloud',
        'CDN — Cloudflare',
        'Email delivery — SMTP2GO',
        'Web platform — WordPress · Static',
        'Booking platform — Latepoint',
      ],
      infra: [
        'RMM — Datto',
        'AV / EDR / XDR / MDR — Sophos · Datto',
        'BCDR — Datto · MSP360 · AWS · Azure',
        'Switching — Aruba InstantON · Sophos · Alta',
        'Firewall — Sophos',
        'WiFi — Alta · Unifi · Sophos',
        'Servers & Endpoints — Lenovo',
        'IPTV — Lemco · VoIP — 3CX',
        'WAN balancer — Sophos · Peplink',
        'Internet — Starlink · OTE DIA',
      ],
    },
  },

  pricing: {
    eyebrow: 'Pricing',
    title: 'Transparent pricing, no hidden charges',
    lead: 'Prices exclude VAT. Get in touch for a quote tailored to your setup.',
    from: 'from',
    cta: 'Request a quote',
    plans: [
      {
        name: 'Hourly Support',
        price: '€40',
        unit: '/ hour',
        featured: false,
        text: 'No hidden charges — all our work is billed at a flat hourly rate.',
        features: [
          'Rate for clients under contract',
          'Contract: 100+ hours per year, used or prepaid',
          'Applies to remote work',
          'On-site support: +€10 per incident',
          'Work outside contract: from €60/hour',
        ],
      },
      {
        name: 'Security Package',
        price: '€5.5',
        unit: '/ device / month',
        featured: true,
        text: 'Complete protection for desktops, laptops and servers at a single price.',
        features: [
          'RMM — remote monitoring and management',
          'Antivirus & EDR',
          'Ransomware protection',
          'With hourly cloud backup: €13.5 / device',
          'BCDR and MDR options available as an upgrade',
        ],
      },
      {
        name: 'Web Hosting',
        price: '€100',
        unit: '/ year',
        featured: false,
        text: 'Secure hosting with zero downtime and fast delivery through a CDN.',
        features: [
          'CDN for fast access worldwide',
          'Data protection',
          'Reliable contact forms',
          'Uptime monitoring',
        ],
      },
      {
        name: 'Microsoft 365',
        price: '€2.1',
        unit: '/ user / month',
        featured: false,
        text: 'Official Microsoft reseller, at exactly the official list prices.',
        features: [
          'Kiosk — Outlook & Teams for frontline staff',
          'Basic — essential productivity tools',
          'Standard — the full desktop app suite',
          'Migration to Microsoft 365: from €20/user one-off',
          'Email & file backup: from €2.5/user',
        ],
      },
    ],
    note:
      'Microsoft 365 pricing follows the official Microsoft list. Your final proposal is prepared after we review your requirements.',
  },

  team: {
    eyebrow: 'Our team',
    title: 'People who will actually pick up the phone',
    members: [
      {
        name: 'Ioannis Kokkinis',
        role: 'President & CEO',
        bio: 'With many years of experience in technology, he leads our team with vision and commitment, making sure clients get innovative, dependable solutions.',
      },
      {
        name: 'Dionysis A.',
        role: 'IT Support Technician',
        bio: 'Always available for fast, reliable help. With deep knowledge and experience, he makes sure technical issues are resolved quickly and effectively.',
      },
      {
        name: 'Christos K.',
        role: 'On Site Technician',
        bio: 'Provides specialist support directly at your premises, making sure your equipment runs flawlessly.',
      },
      {
        name: 'Elizabeth Vidler',
        role: 'Procurement',
        bio: 'Secures the best products and services for our clients, with attention to detail and a strong grasp of the market.',
      },
    ],
  },

  clients: {
    eyebrow: 'Our clients',
    title: 'Some of the companies that trusted us',
    lead: 'Businesses that chose us as their technology partner.',
    tabs: {
      web: 'Web',
      infra: 'IT Infrastructure',
      security: 'Security & BCDR',
      telephony: 'Telephony',
      iptv: 'IPTV & Streaming',
    },
  },

  projects: {
    eyebrow: 'Projects',
    title: 'Infrastructure we run every day',
    lead:
      'Websites we designed, host and support — including work shared with our sister company Buy IT.',
    all: 'All',
    beyondWeb: 'Beyond websites',
    reach: {
      microsoft365: 'Businesses on Microsoft 365',
      hosting: 'On managed web hosting',
      domains: 'With managed domains',
      security: 'With protection & backup',
      cloud: 'On cloud infrastructure',
      booking: 'With a booking system',
    },
    beyondWebLead:
      'Websites are only part of it. Below is how many businesses we actively support on each service.',
    visit: 'Visit',
    showMore: 'More projects',
    countLabel: 'projects',
    viewAll: 'View all projects',
    categories: {
      'Web Design': 'Web Design',
      'Web Hosting': 'Web Hosting',
      'DNS Management': 'DNS Management',
      Cybersecurity: 'Cybersecurity',
      'Microsoft 365': 'Microsoft 365',
      'Cloud Infrastructure': 'Cloud Infrastructure',
      'Web Services': 'Web Services',
      VoIP: 'VoIP',
      Networking: 'Networking',
      'Managed IT': 'Managed IT',
    },
  },

  security: {
    eyebrow: 'Cyber Security',
    title: 'Is your data at risk?',
    lead: 'A guide to building a properly secured office or hotel.',
    intro:
      'Businesses today have to manage a growing amount of cyber risk. Whether you run an office or a hotel, an effective cybersecurity strategy is essential.',
    toc: 'Contents',
    ctaTitle: 'Want a security review of your site?',
    ctaText:
      'We audit your existing infrastructure and come back with concrete, costed next steps.',
  },

  products: {
    eyebrow: 'Products',
    title: 'Smart Home & IoT',
    lead: 'Devices we install and support, also available to buy directly.',
    price: 'Price',
    ean: 'EAN',
    specs: 'Specifications',
    ask: 'Ask us',
  },

  contact: {
    eyebrow: 'Contact',
    title: "Let's talk about your infrastructure",
    lead: 'Email or call us — we reply the same working day.',
    emailLabel: 'Email',
    emailHint: 'Send us an email',
    phoneLabel: 'Phone',
    phoneHint: 'Give us a call',
    officesTitle: 'Offices',
    offices: [
      { name: 'Zakynthos Town', note: 'UPGRADE' },
      { name: 'Tragaki', note: 'Buy IT' },
    ],
    mapLabel: 'Office map',
    openInMaps: 'Open in Maps',
  },

  footer: {
    tagline:
      'End-to-end IT services, security and cloud infrastructure for businesses in Zakynthos and across Greece.',
    solutions: 'Services',
    company: 'Company',
    contact: 'Contact',
    sister: 'Sister company',
    rights: 'All rights reserved.',
    iso: 'ISO 9001 certified',
    social: 'Social',
  },
} as const;
