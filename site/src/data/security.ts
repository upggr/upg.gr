/**
 * The cybersecurity guide, carried over from the previous page2.html and
 * restructured. `body` entries render as paragraphs, `list` as bullet lists.
 */
type Block =
  | { type: 'p'; text: string }
  | { type: 'list'; items: string[] }
  | { type: 'h3'; text: string };

export interface Chapter {
  id: string;
  title: string;
  blocks: Block[];
}

export const securityChapters: Record<'el' | 'en', Chapter[]> = {
  el: [
    {
      id: 'firewall',
      title: 'Firewall: Η πρώτη γραμμή άμυνας',
      blocks: [
        {
          type: 'p',
          text: 'Ένα επαγγελματικό περιβάλλον χρειάζεται Next-Generation Firewall (NGFW). Προτείνουμε τα Sophos Firewalls, καθώς παρέχουν εξελιγμένες δυνατότητες όπως ανίχνευση εισβολών (IDS/IPS) και προστασία από κακόβουλες επιθέσεις.',
        },
        {
          type: 'p',
          text: 'Για τον υπολογισμό του μεγέθους ενός firewall, ο βασικός παράγοντας είναι ο αριθμός των «πλήρων χρηστών» (full users) που χρησιμοποιούν προηγμένες δυνατότητες, όπως IDS/IPS και web filtering.',
        },
        { type: 'h3', text: 'Εκτίμηση μεγέθους' },
        {
          type: 'list',
          items: [
            'Γραφείο με 10 χρήστες: όλοι θεωρούνται πλήρεις χρήστες — χρειάζεστε firewall για 10 πλήρεις χρήστες.',
            'Ξενοδοχείο με 5 χρήστες back-office και 200 χρήστες Wi-Fi: οι 5 είναι πλήρεις χρήστες, ενώ οι 200 δεν χρησιμοποιούν προηγμένες δυνατότητες — πρέπει όμως να τοποθετηθούν σε ξεχωριστό VLAN.',
            'Γραφείο 10 χρηστών: Sophos XGS 87 ή XGS 107 — από €900–1200 με την προστασία.',
            'Ξενοδοχείο 5 back-office + 200 Wi-Fi: Sophos XGS 116 ή XGS 136 — από €1200–1500 με την προστασία.',
          ],
        },
        {
          type: 'p',
          text: 'Σημείωση: η τελική επιλογή εξαρτάται από την ταχύτητα της σύνδεσης internet, τις απαιτήσεις throughput και τον αριθμό ταυτόχρονων συνδέσεων.',
        },
      ],
    },
    {
      id: 'antivirus',
      title: 'Antivirus & EDR: Πολυεπίπεδη προστασία',
      blocks: [
        {
          type: 'p',
          text: 'Η εγκατάσταση κορυφαίου antivirus είναι απαραίτητη για όλα τα endpoints. Επιλέξτε λύσεις με real-time ανίχνευση απειλών, αυτόματη απομόνωση μολυσμένων αρχείων και κεντρική διαχείριση μέσω cloud.',
        },
        {
          type: 'p',
          text: 'Το Sophos Intercept X προσφέρει ολοκληρωμένη προστασία από ransomware, malware και exploits, με deep learning για ανίχνευση χωρίς υπογραφή, anti-ransomware που σταματά την κρυπτογράφηση αρχείων και λειτουργία rollback.',
        },
        {
          type: 'list',
          items: [
            'Servers: Sophos Intercept X for Server with XDR — ανίχνευση και απόκριση σε multi-cloud, on-premises ή υβριδικά περιβάλλοντα.',
            'Desktops και κινητά: Intercept X Advanced, με προστασία κινητών μέσω Sophos Mobile.',
            'Desktop/Mobile protection: περίπου €35–€50 ανά χρήστη ή συσκευή ετησίως.',
            'Server protection: από €150–€250 ανά server ετησίως, ανάλογα με τα χαρακτηριστικά.',
            'Εναλλακτικά, Datto Antivirus με Anti-Ransomware: περίπου €30–€45 ανά συσκευή ετησίως, σε συνδυασμό με το RMM.',
          ],
        },
      ],
    },
    {
      id: 'rmm',
      title: 'RMM για patching και ενημερώσεις',
      blocks: [
        {
          type: 'p',
          text: 'Το RMM (Remote Monitoring and Management) είναι το εργαλείο με το οποίο η εταιρεία υποστήριξής σας διαχειρίζεται και προστατεύει το δίκτυό σας.',
        },
        {
          type: 'list',
          items: [
            'Εύκολη διαχείριση: παρακολούθηση συστημάτων σε πραγματικό χρόνο, διαχείριση ενημερώσεων και patches.',
            'Ασφαλής απομακρυσμένη πρόσβαση μέσω ασφαλών καναλιών, χωρίς εργαλεία όπως TeamViewer ή AnyDesk που ενδέχεται να ενέχουν κενά ασφαλείας.',
            'Έλεγχος εφαρμογών: αποτρέπει την εγκατάσταση μη εξουσιοδοτημένων προγραμμάτων.',
            'Πρόταση: Datto RMM μαζί με Datto Antivirus και Anti-Ransomware, με συνολική τιμή περίπου €9 ανά θέση εργασίας.',
          ],
        },
      ],
    },
    {
      id: 'bdr',
      title: 'BDR: Backup και Disaster Recovery',
      blocks: [
        {
          type: 'p',
          text: 'Το BDR είναι κρίσιμο για τη συνέχεια της επιχείρησης σε περίπτωση απώλειας δεδομένων ή διακοπής λειτουργίας. Με το σωστό σύστημα μπορείτε να επαναφέρετε δεδομένα με ακρίβεια και να διατηρήσετε τη λειτουργία σας.',
        },
        {
          type: 'list',
          items: [
            'Cloud backup: αντίγραφα ασφαλείας στο cloud κάθε ώρα.',
            'Endpoint backup: κάλυψη και για PCs και laptops.',
            'Γρήγορη ανάκτηση: ένα αρχείο από συγκεκριμένη ημερομηνία, ή μια εγγραφή σε κελί Excel τριών μηνών πριν, σε λίγα λεπτά.',
            'Ασφάλεια εντός και εκτός επιχείρησης: τοπική και cloud αποθήκευση, προστασία ακόμα και σε φυσικές καταστροφές.',
            'Αυτοματοποιημένο και αξιόπιστο, χωρίς ανθρώπινη παρέμβαση.',
            'Η τιμή μας: €8 ανά υπολογιστή ή server, με backup κάθε ώρα στο cloud.',
          ],
        },
      ],
    },
    {
      id: 'microsoft365',
      title: 'Microsoft 365 & SaaS backup',
      blocks: [
        {
          type: 'p',
          text: 'Το Microsoft 365 προσφέρει παραγωγικότητα, ασφάλεια και ευελιξία. Με OneDrive και SharePoint αποκτάτε ισχυρή υποδομή για αποθήκευση, διαμοιρασμό και συνεργασία σε αρχεία.',
        },
        {
          type: 'list',
          items: [
            'Επαγγελματική αξιοπιστία με email στο δικό σας domain.',
            'Ενοποίηση με Teams, Planner και Outlook.',
            'Ασφάλεια μέσω Defender for Office 365 έναντι phishing και malware.',
          ],
        },
        { type: 'h3', text: 'Γιατί χρειάζεστε SaaS backup' },
        {
          type: 'p',
          text: 'Παρότι το Microsoft 365 προσφέρει υψηλά επίπεδα προστασίας, δεν περιλαμβάνει ενσωματωμένο εργαλείο για αναλυτικό backup. Δεν σας προστατεύει από ανθρώπινα λάθη, κακόβουλες ενέργειες ή πολιτικές περιορισμένου retention.',
        },
        {
          type: 'list',
          items: [
            'Microsoft 365 Kiosk (F1/F3): email μέσω Outlook Web App και Teams — περίπου €2–€3 ανά χρήστη/μήνα.',
            'Microsoft 365 Business Basic: Exchange Online 50GB, OneDrive 1TB, web εφαρμογές — περίπου €5–€6 ανά χρήστη/μήνα.',
            'Microsoft 365 Business Standard: όλα τα παραπάνω και εγκαταστάσιμες εφαρμογές Office — περίπου €11–€12 ανά χρήστη/μήνα.',
            'Datto SaaS Backup: από €3 ανά χρήστη, με backup σε Microsoft 365 ή Google Workspace.',
          ],
        },
      ],
    },
    {
      id: 'pentest',
      title: 'Pen test και ασφαλιστική κάλυψη',
      blocks: [
        {
          type: 'p',
          text: 'Η συμμόρφωση με τα πρότυπα ασφάλειας και η επιτυχία σε ένα penetration test είναι απαραίτητες για την προστασία της επιχείρησης και την εξασφάλιση κάλυψης από ασφαλιστικές εταιρείες.',
        },
        { type: 'h3', text: 'Υποστηριζόμενες συσκευές & αναβαθμίσεις' },
        {
          type: 'list',
          items: [
            'Όλες οι συσκευές, από υπολογιστές έως εκτυπωτές, πρέπει να είναι εντός υποστήριξης από τον κατασκευαστή.',
            'Υπολογιστές με Windows 7 δεν λαμβάνουν ενημερώσεις ασφαλείας από το 2020.',
            'Παλιοί εκτυπωτές δεν υποστηρίζουν σύγχρονα πρωτόκολλα και μπορούν να γίνουν πύλες επίθεσης.',
          ],
        },
        { type: 'h3', text: 'Information leak & dark web' },
        {
          type: 'list',
          items: [
            'Οι παραβιάσεις οδηγούν σε διαρροές διαπιστευτηρίων και οικονομικών δεδομένων στο dark web.',
            'Συνέπειες: μη εξουσιοδοτημένη πρόσβαση και απώλεια εμπιστοσύνης πελατών.',
            'Λύση: εργαλεία dark web monitoring για έγκαιρο εντοπισμό και προληπτικά μέτρα.',
          ],
        },
        { type: 'h3', text: 'Ασφάλεια κινητών συσκευών (BYOD)' },
        {
          type: 'list',
          items: [
            'Μη ασφαλή δημόσια Wi-Fi δίκτυα θέτουν σε κίνδυνο εταιρικά δεδομένα.',
            'Χωρίς MDM δεν υπάρχει έλεγχος για το τι εγκαθιστούν οι χρήστες.',
            'Προτάσεις: υιοθέτηση MDM και ενεργοποίηση VPN για ασφαλή πρόσβαση.',
          ],
        },
        { type: 'h3', text: 'Εκπαίδευση προσωπικού & πολιτικές' },
        {
          type: 'list',
          items: [
            'Μεταφορά χρημάτων χωρίς πολλαπλή επαλήθευση και άνοιγμα phishing emails είναι συνήθεις κίνδυνοι.',
            'Εκπαίδευση προσωπικού σε κυβερνοαπειλές και διεξαγωγή phishing tests.',
            'Τακτικές αναβαθμίσεις λογισμικού και firmware.',
            'Πολιτικές ελάχιστων δικαιωμάτων πρόσβασης (least privilege).',
            'Επαρκείς διαδικασίες ανίχνευσης και απόκρισης σε περιστατικά.',
          ],
        },
      ],
    },
  ],

  en: [
    {
      id: 'firewall',
      title: 'Firewall: your first line of defence',
      blocks: [
        {
          type: 'p',
          text: 'A professional environment needs a Next-Generation Firewall (NGFW). We recommend Sophos firewalls for their advanced capabilities, including intrusion detection (IDS/IPS) and protection against malicious attacks.',
        },
        {
          type: 'p',
          text: 'When sizing a firewall, the key factor is the number of "full users" — the people using advanced features such as IDS/IPS and web filtering.',
        },
        { type: 'h3', text: 'Sizing examples' },
        {
          type: 'list',
          items: [
            'A 10-person office: everyone counts as a full user, so you need a firewall rated for 10 full users.',
            'A hotel with 5 back-office staff and 200 Wi-Fi guests: the 5 are full users; the 200 guests do not use advanced features but must sit on a separate VLAN.',
            '10-user office: Sophos XGS 87 or XGS 107 — from €900–1200 including protection.',
            'Hotel, 5 back-office + 200 Wi-Fi: Sophos XGS 116 or XGS 136 — from €1200–1500 including protection.',
          ],
        },
        {
          type: 'p',
          text: 'Note: the final choice depends on your internet speed, throughput requirements and the number of concurrent connections.',
        },
      ],
    },
    {
      id: 'antivirus',
      title: 'Antivirus & EDR: layered protection',
      blocks: [
        {
          type: 'p',
          text: 'Top-tier antivirus is essential on every endpoint. Choose solutions with real-time threat detection, automatic quarantine of infected files and central cloud management.',
        },
        {
          type: 'p',
          text: 'Sophos Intercept X provides complete protection against ransomware, malware and exploits, using deep learning for signature-less detection, anti-ransomware that halts file encryption, and rollback for affected files.',
        },
        {
          type: 'list',
          items: [
            'Servers: Sophos Intercept X for Server with XDR — detection and response across multi-cloud, on-premises or hybrid environments.',
            'Desktops and mobiles: Intercept X Advanced, with mobile protection through Sophos Mobile.',
            'Desktop/mobile protection: roughly €35–€50 per user or device per year.',
            'Server protection: from €150–€250 per server per year, depending on features.',
            'Alternatively Datto Antivirus with Anti-Ransomware: roughly €30–€45 per device per year, paired with RMM.',
          ],
        },
      ],
    },
    {
      id: 'rmm',
      title: 'RMM for patching and updates',
      blocks: [
        {
          type: 'p',
          text: 'RMM (Remote Monitoring and Management) is the tool your support company uses to manage and protect your network effectively.',
        },
        {
          type: 'list',
          items: [
            'Easy management: real-time system monitoring, update and patch management.',
            'Secure remote access over hardened channels, avoiding tools like TeamViewer or AnyDesk that can introduce security gaps.',
            'Application control: stops staff installing unauthorised software.',
            'Our recommendation: Datto RMM together with Datto Antivirus and Anti-Ransomware, at roughly €9 per workstation.',
          ],
        },
      ],
    },
    {
      id: 'bdr',
      title: 'BDR: backup and disaster recovery',
      blocks: [
        {
          type: 'p',
          text: 'BDR is critical to business continuity in the event of data loss or an outage. With the right system you can restore data precisely and keep operating.',
        },
        {
          type: 'list',
          items: [
            'Cloud backup: copies stored in the cloud every hour.',
            'Endpoint backup: PCs and laptops covered as well.',
            'Fast recovery: a file from a specific date, or a cell in an Excel sheet from three months ago, within minutes.',
            'Protected on and off site: local and cloud storage, safe even in a physical disaster.',
            'Automated and dependable, with no human intervention required.',
            'Our price: €8 per computer or server, with hourly cloud backup.',
          ],
        },
      ],
    },
    {
      id: 'microsoft365',
      title: 'Microsoft 365 & SaaS backup',
      blocks: [
        {
          type: 'p',
          text: 'Microsoft 365 delivers productivity, security and flexibility. With OneDrive and SharePoint you gain solid infrastructure for storing, sharing and collaborating on files.',
        },
        {
          type: 'list',
          items: [
            'Professional credibility with email on your own domain.',
            'Integration with Teams, Planner and Outlook.',
            'Security through Defender for Office 365 against phishing and malware.',
          ],
        },
        { type: 'h3', text: 'Why you still need SaaS backup' },
        {
          type: 'p',
          text: 'Although Microsoft 365 offers strong data protection, it includes no granular backup tool. It does not protect you from human error, malicious deletion, or limited retention policies.',
        },
        {
          type: 'list',
          items: [
            'Microsoft 365 Kiosk (F1/F3): email via Outlook Web App and Teams — roughly €2–€3 per user/month.',
            'Microsoft 365 Business Basic: Exchange Online 50GB, OneDrive 1TB, web apps — roughly €5–€6 per user/month.',
            'Microsoft 365 Business Standard: everything above plus installable Office apps — roughly €11–€12 per user/month.',
            'Datto SaaS Backup: from €3 per user, backing up Microsoft 365 or Google Workspace.',
          ],
        },
      ],
    },
    {
      id: 'pentest',
      title: 'Passing a pen test and securing cyber insurance',
      blocks: [
        {
          type: 'p',
          text: 'Meeting security standards and passing a penetration test are essential both to protect your business and to earn the confidence of cyber insurers.',
        },
        { type: 'h3', text: 'Supported devices & upgrades' },
        {
          type: 'list',
          items: [
            'Every device, from computers to printers, must still be supported by its manufacturer.',
            'Windows 7 machines have received no security updates since 2020.',
            'Older printers lack modern security protocols and can become an entry point for attacks.',
          ],
        },
        { type: 'h3', text: 'Information leaks & the dark web' },
        {
          type: 'list',
          items: [
            'Breaches routinely leak credentials and financial data onto the dark web.',
            'Consequences: unauthorised account access and loss of customer trust.',
            'Solution: dark web monitoring tools to spot leaks early and act preemptively.',
          ],
        },
        { type: 'h3', text: 'Mobile device security (BYOD)' },
        {
          type: 'list',
          items: [
            'Unsecured public Wi-Fi puts company data at risk.',
            'Without MDM there is no control over what users install.',
            'Recommendations: adopt MDM and enable VPN for secure access to company data.',
          ],
        },
        { type: 'h3', text: 'Staff training & policies' },
        {
          type: 'list',
          items: [
            'Transferring money without multi-step verification and opening phishing emails are common risks.',
            'Train staff on cyber threats and run phishing tests to gauge exposure.',
            'Keep software and firmware regularly updated.',
            'Enforce least-privilege access policies.',
            'Maintain adequate incident detection and response procedures.',
          ],
        },
      ],
    },
  ],
};
