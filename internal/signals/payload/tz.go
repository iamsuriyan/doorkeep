package payload

// tzStdOffsets maps common IANA zones to their standard UTC offset in
// minutes (east positive). Used only for the id-vs-offset consistency check;
// zones not listed are skipped (neutral).
var tzStdOffsets = map[string]int{
	"UTC": 0, "Etc/UTC": 0, "Etc/GMT": 0, "GMT": 0,
	"Europe/London": 0, "Europe/Dublin": 0, "Europe/Lisbon": 0,
	"Europe/Paris": 60, "Europe/Berlin": 60, "Europe/Madrid": 60, "Europe/Rome": 60,
	"Europe/Amsterdam": 60, "Europe/Brussels": 60, "Europe/Vienna": 60, "Europe/Stockholm": 60,
	"Europe/Oslo": 60, "Europe/Copenhagen": 60, "Europe/Warsaw": 60, "Europe/Prague": 60,
	"Europe/Zurich": 60, "Europe/Budapest": 60,
	"Europe/Athens": 120, "Europe/Helsinki": 120, "Europe/Kiev": 120, "Europe/Kyiv": 120,
	"Europe/Bucharest": 120, "Africa/Cairo": 120, "Africa/Johannesburg": 120,
	"Europe/Istanbul": 180, "Europe/Moscow": 180, "Asia/Riyadh": 180, "Africa/Nairobi": 180,
	"Asia/Dubai": 240, "Asia/Karachi": 300, "Asia/Tashkent": 300,
	"Asia/Kolkata": 330, "Asia/Calcutta": 330, "Asia/Colombo": 330, "Asia/Kathmandu": 345,
	"Asia/Dhaka": 360, "Asia/Yangon": 390, "Asia/Bangkok": 420, "Asia/Jakarta": 420,
	"Asia/Ho_Chi_Minh": 420, "Asia/Shanghai": 480, "Asia/Hong_Kong": 480, "Asia/Singapore": 480,
	"Asia/Taipei": 480, "Asia/Manila": 480, "Asia/Kuala_Lumpur": 480, "Australia/Perth": 480,
	"Asia/Tokyo": 540, "Asia/Seoul": 540, "Australia/Adelaide": 570, "Australia/Darwin": 570,
	"Australia/Sydney": 600, "Australia/Melbourne": 600, "Australia/Brisbane": 600,
	"Pacific/Auckland":  720,
	"America/Sao_Paulo": -180, "America/Argentina/Buenos_Aires": -180, "America/Santiago": -240,
	"America/Halifax": -240, "America/Caracas": -240, "America/New_York": -300,
	"America/Toronto": -300, "America/Bogota": -300, "America/Lima": -300,
	"America/Chicago": -360, "America/Mexico_City": -360, "America/Denver": -420,
	"America/Phoenix": -420, "America/Los_Angeles": -480, "America/Vancouver": -480,
	"America/Anchorage": -540, "Pacific/Honolulu": -600,
}

// tzCountry maps common IANA zones to an ISO 3166-1 alpha-2 country
// (lowercase). Zones not listed yield "" (unknown, neutral).
var tzCountry = map[string]string{
	"Europe/London": "gb", "Europe/Dublin": "ie", "Europe/Lisbon": "pt", "Europe/Paris": "fr",
	"Europe/Berlin": "de", "Europe/Madrid": "es", "Europe/Rome": "it", "Europe/Amsterdam": "nl",
	"Europe/Brussels": "be", "Europe/Vienna": "at", "Europe/Stockholm": "se", "Europe/Oslo": "no",
	"Europe/Copenhagen": "dk", "Europe/Warsaw": "pl", "Europe/Prague": "cz", "Europe/Zurich": "ch",
	"Europe/Budapest": "hu", "Europe/Athens": "gr", "Europe/Helsinki": "fi", "Europe/Kiev": "ua",
	"Europe/Kyiv": "ua", "Europe/Bucharest": "ro", "Africa/Cairo": "eg", "Africa/Johannesburg": "za",
	"Europe/Istanbul": "tr", "Europe/Moscow": "ru", "Asia/Riyadh": "sa", "Africa/Nairobi": "ke",
	"Asia/Dubai": "ae", "Asia/Karachi": "pk", "Asia/Tashkent": "uz", "Asia/Kolkata": "in",
	"Asia/Calcutta": "in", "Asia/Colombo": "lk", "Asia/Kathmandu": "np", "Asia/Dhaka": "bd",
	"Asia/Yangon": "mm", "Asia/Bangkok": "th", "Asia/Jakarta": "id", "Asia/Ho_Chi_Minh": "vn",
	"Asia/Shanghai": "cn", "Asia/Hong_Kong": "hk", "Asia/Singapore": "sg", "Asia/Taipei": "tw",
	"Asia/Manila": "ph", "Asia/Kuala_Lumpur": "my", "Australia/Perth": "au", "Asia/Tokyo": "jp",
	"Asia/Seoul": "kr", "Australia/Adelaide": "au", "Australia/Darwin": "au", "Australia/Sydney": "au",
	"Australia/Melbourne": "au", "Australia/Brisbane": "au", "Pacific/Auckland": "nz",
	"America/Sao_Paulo": "br", "America/Argentina/Buenos_Aires": "ar", "America/Santiago": "cl",
	"America/Halifax": "ca", "America/Caracas": "ve", "America/New_York": "us", "America/Toronto": "ca",
	"America/Bogota": "co", "America/Lima": "pe", "America/Chicago": "us", "America/Mexico_City": "mx",
	"America/Denver": "us", "America/Phoenix": "us", "America/Los_Angeles": "us",
	"America/Vancouver": "ca", "America/Anchorage": "us", "Pacific/Honolulu": "us",
}
