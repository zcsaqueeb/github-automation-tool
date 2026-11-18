"""Small, dependency-free UI translations for the Telegram bot."""

LANGUAGES = {
    "en": "English",
    "hi": "हिन्दी",
    "bn": "বাংলা",
    "es": "Español",
}

_TEXT = {
    "en": {
        "home": "Home",
        "new_repo": "New Repo",
        "ai_suggest": "AI Suggest Repo",
        "archive": "Archive Upload",
        "fork": "Fork Repo",
        "my_repos": "My Repos",
        "edit_repo": "Edit Repo",
        "download": "Download Repo",
        "star": "Star Repo",
        "delete": "Delete Repo",
        "replace": "Replace Repo",
        "upload_files": "Upload to Repo",
        "live_preview": "Live Preview",
        "accounts": "My Accounts",
        "models": "AI Models",
        "status": "Status",
        "extras": "GitHub Extras",
        "history": "History",
        "help": "Help",
        "guide": "Guide",
        "setup": "Setup",
        "support": "Support",
        "admin": "Admin Panel",
        "language": "Language",
        "timezone": "Time zone",
        "home_title": "🏠 *Home* - What would you like to do?",
        "welcome": "🚀 *GitHub AI Repo Bot*\n\nManage GitHub repositories from Telegram.\n\nSend `/guide` to connect GitHub and an AI provider. Use the menu to create or manage repositories.",
        "language_title": "🌐 Choose your language",
        "language_current": "Current language: {language}",
        "language_saved": "Language changed to {language}.",
        "timezone_title": "🕒 Choose your time zone",
        "timezone_current": "Current: {zone}",
        "timezone_hint": "Choose a common zone below, or send `/timezone Area/City` for any IANA time zone.",
        "timezone_saved": "Time zone changed to {zone}.",
        "timezone_invalid": "That time zone is not recognized. Try a name such as `Asia/Kolkata`.",
        "history_title": "📜 *Recent Activity*",
        "history_empty": "No history yet. Create your first repository to see activity here.",
        "history_summary": "Showing {start}-{end} of {total} actions - Page {page}/{pages}",
        "history_create": "Create Repository",
        "previous": "◀ Previous",
        "next": "Next ▶",
        "models_title": "🤖 *AI Providers and Suggested Models*",
        "free": "FREE",
        "paid": "Paid",
        "suggested": "Suggested",
        "also": "Also",
        "set_model": "Set",
        "status_title": "Account Status",
        "github": "GitHub",
        "ai_provider": "AI Provider",
        "not_set": "Not set",
        "token_invalid": "Token invalid or expired",
        "not_configured": "Not configured",
        "activity_stats": "Activity Stats",
        "repos_created": "Repos created",
        "repos_deleted": "Repos deleted",
        "repos_cleared": "Repos cleared",
        "repos_forked": "Repos forked",
        "repos_starred": "Repos starred",
        "archives_uploaded": "Archives uploaded",
        "files_pushed": "Files pushed",
        "contributions": "Contributions",
        "total_actions": "total actions",
        "member_since": "Member since",
        "loaded_in": "Loaded in",
        "help_text": (
            "🧭 *Help and commands*\n\n*Setup*\n"
            "`/start` - Open the main menu\n`/guide` - Setup instructions\n"
            "`/setgithub` - Connect GitHub\n`/setai` - Choose an AI provider\n"
            "`/models` - View providers and models\n\n*Repositories*\n"
            "`/create_new_repo` - Create a repository\n`/suggest` - Generate one from an idea\n"
            "`/list_repos` - Browse repositories\n`/import_repo [URL]` - Fork a repository\n"
            "`/delete_repo` - Delete repositories\n`/replace_repo` - Clear a repo's files, keep the repo\n"
            "`/star_repo OWNER/REPO` - Star a repository\n\n"
            "*Account*\n`/status` - Check connections and activity\n"
            "`/accounts` - Manage multiple GitHub accounts\n"
            "`/history` - View recent activity\n`/support` - Contact support\n\n"
            "Use the buttons in the main menu if you prefer not to type commands."
        ),
        "guide_text": (
            "📖 *Quick Setup Guide*\n\n*1. Connect GitHub*\n"
            "Create a personal access token in GitHub Settings > Developer settings. "
            "Grant the repository permissions you need; deleting repositories requires delete permission.\n"
            "Send `/setgithub` and follow the prompt.\n\n*2. Connect AI (optional)*\n"
            "Run `/models` to see supported providers. Create a provider API key, then run `/setai`.\n\n"
            "*3. Create a repository*\nUse *New Repo* to create one step by step, or *AI Suggest Repo* "
            "to start from an idea. You can also upload a supported archive.\n\n"
            "*4. Check your setup*\nRun `/status` for connection status and `/history` for recent actions.\n\n"
            "🔐 Send tokens only in this private chat. The bot removes token messages after reading them. "
            "Never share tokens with anyone. Connect several accounts with `/accounts` and switch in one tap. "
            "Use `/help` for commands."
        ),
        "admin_help": "\n\n*Admin commands*\n`/admin` - Open user and bot controls\n`/ban USER_ID` and `/unban USER_ID` - Manage access\n`/broadcast` - Send an announcement\n`/addadmin USER_ID` and `/removeadmin USER_ID` - Manage admins",
    },
    "hi": {
        "home": "होम", "new_repo": "नया रिपॉज़िटरी", "ai_suggest": "AI से रिपॉज़िटरी सुझाव",
        "archive": "आर्काइव अपलोड", "fork": "रिपॉज़िटरी फोर्क करें", "my_repos": "मेरे रिपॉज़िटरी",
        "edit_repo": "रिपॉज़िटरी संपादित करें", "download": "रिपॉज़िटरी डाउनलोड", "star": "स्टार करें",
        "delete": "रिपॉज़िटरी हटाएँ", "replace": "रिपॉज़िटरी बदलें", "upload_files": "रिपॉज़िटरी में अपलोड करें", "live_preview": "लाइव प्रीव्यू", "models": "AI मॉडल", "status": "स्थिति", "accounts": "मेरे खाते", "extras": "GitHub सुविधाएँ",
        "history": "इतिहास", "help": "मदद", "guide": "गाइड", "setup": "सेटअप", "support": "सहायता",
        "admin": "एडमिन पैनल", "language": "भाषा", "home_title": "🏠 *होम* - आप क्या करना चाहेंगे?",
        "language_title": "🌐 अपनी भाषा चुनें", "language_current": "वर्तमान भाषा: {language}",
        "timezone": "समय क्षेत्र",
        "timezone_title": "🕒 अपना समय क्षेत्र चुनें", "timezone_current": "वर्तमान: {zone}",
        "timezone_hint": "नीचे से समय क्षेत्र चुनें या कोई भी IANA समय क्षेत्र `/timezone Area/City` भेजें।",
        "timezone_saved": "समय क्षेत्र {zone} कर दिया गया है।",
        "timezone_invalid": "समय क्षेत्र पहचान में नहीं आया। `Asia/Kolkata` जैसे नाम का उपयोग करें।",
        "welcome": "🚀 *GitHub AI Repo Bot*\n\nTelegram से GitHub रिपॉज़िटरी प्रबंधित करें।\n\nGitHub और AI जोड़ने के लिए `/guide` भेजें। रिपॉज़िटरी बनाने या प्रबंधित करने के लिए मेनू का उपयोग करें।",
        "language_saved": "भाषा {language} कर दी गई है।", "history_title": "📜 *हाल की गतिविधि*",
        "history_empty": "अभी कोई इतिहास नहीं है। गतिविधि देखने के लिए पहली रिपॉज़िटरी बनाएँ।",
        "history_summary": "{total} में से {start}-{end} गतिविधियाँ - पृष्ठ {page}/{pages}",
        "history_create": "रिपॉज़िटरी बनाएँ", "previous": "◀ पिछला", "next": "अगला ▶",
        "models_title": "🤖 *AI प्रदाता और सुझाए गए मॉडल*", "free": "मुफ़्त", "paid": "भुगतान वाला",
        "suggested": "सुझाया गया", "also": "अन्य", "set_model": "चुनें",
        "status_title": "खाते की स्थिति", "github": "GitHub", "ai_provider": "AI प्रदाता",
        "not_set": "सेट नहीं है", "token_invalid": "Token अमान्य या समाप्त हो गया है",
        "not_configured": "कॉन्फ़िगर नहीं है", "activity_stats": "गतिविधि आँकड़े",
        "repos_created": "बनाए गए रिपॉज़िटरी", "repos_deleted": "हटाए गए रिपॉज़िटरी",
        "repos_cleared": "साफ़ की गई रिपॉज़िटरी",
        "repos_forked": "फोर्क किए गए रिपॉज़िटरी", "repos_starred": "स्टार किए गए रिपॉज़िटरी",
        "archives_uploaded": "अपलोड किए गए आर्काइव", "files_pushed": "अपलोड की गई फ़ाइलें",
        "contributions": "योगदान", "total_actions": "कुल गतिविधियाँ", "member_since": "सदस्यता शुरू",
        "loaded_in": "लोड समय",
        "help_text": (
            "🧭 *मदद और कमांड*\n\n*सेटअप*\n`/start` - मुख्य मेनू खोलें\n"
            "`/guide` - सेटअप निर्देश\n`/setgithub` - GitHub जोड़ें\n`/setai` - AI प्रदाता चुनें\n"
            "`/models` - प्रदाता और मॉडल देखें\n\n*रिपॉज़िटरी*\n`/create_new_repo` - रिपॉज़िटरी बनाएँ\n"
            "`/suggest` - विचार से रिपॉज़िटरी बनाएँ\n`/list_repos` - रिपॉज़िटरी देखें\n"
            "`/import_repo [URL]` - रिपॉज़िटरी फोर्क करें\n`/delete_repo` - रिपॉज़िटरी हटाएँ\n"
            "`/replace_repo` - रिपॉज़िटरी की फ़ाइलें साफ़ करें (रिपॉज़िटरी बनी रहेगी)\n"
            "`/star_repo OWNER/REPO` - स्टार करें\n\n*खाता*\n`/status` - कनेक्शन और गतिविधि देखें\n"
            "`/accounts` - एक से अधिक GitHub खाते प्रबंधित करें\n"
            "`/history` - हाल की गतिविधि\n`/support` - सहायता से संपर्क करें"
        ),
        "guide_text": (
            "📖 *त्वरित सेटअप गाइड*\n\n*1. GitHub जोड़ें*\nGitHub Settings > Developer settings में personal access token बनाएँ। "
            "ज़रूरी repository permissions दें; रिपॉज़िटरी हटाने के लिए delete permission चाहिए।\n"
            "`/setgithub` भेजें और निर्देशों का पालन करें।\n\n*2. AI जोड़ें (वैकल्पिक)*\n"
            "उपलब्ध प्रदाता देखने के लिए `/models` चलाएँ। API key बनाएँ, फिर `/setai` चलाएँ।\n\n"
            "*3. रिपॉज़िटरी बनाएँ*\n*New Repo* से चरण-दर-चरण बनाएँ या *AI Suggest Repo* से विचार शुरू करें। "
            "आप समर्थित archive भी अपलोड कर सकते हैं।\n\n*4. सेटअप जाँचें*\n`/status` कनेक्शन दिखाता है और `/history` हाल की गतिविधि।\n\n"
            "🔐 Token केवल इस निजी चैट में भेजें। पढ़ने के बाद bot token वाला संदेश हटा देता है।"
        ),
        "admin_help": "\n\n*एडमिन कमांड*\n`/admin` - बॉट नियंत्रण खोलें\n`/ban USER_ID` और `/unban USER_ID` - पहुँच प्रबंधित करें\n`/broadcast` - घोषणा भेजें\n`/addadmin USER_ID` और `/removeadmin USER_ID` - एडमिन प्रबंधित करें",
    },
    "bn": {
        "home": "হোম", "new_repo": "নতুন রিপোজিটরি", "ai_suggest": "AI রিপোজিটরি প্রস্তাব",
        "archive": "আর্কাইভ আপলোড", "fork": "রিপোজিটরি ফর্ক", "my_repos": "আমার রিপোজিটরি",
        "edit_repo": "রিপোজিটরি সম্পাদনা", "download": "রিপোজিটরি ডাউনলোড", "star": "স্টার দিন",
        "delete": "রিপোজিটরি মুছুন", "replace": "রিপোজিটরি প্রতিস্থাপন", "upload_files": "রিপোজিটরিতে আপলোড", "live_preview": "লাইভ প্রিভিউ", "models": "AI মডেল", "status": "অবস্থা", "accounts": "আমার অ্যাকাউন্ট", "extras": "GitHub টুল",
        "history": "ইতিহাস", "help": "সাহায্য", "guide": "নির্দেশিকা", "setup": "সেটআপ", "support": "সহায়তা",
        "admin": "অ্যাডমিন প্যানেল", "language": "ভাষা", "home_title": "🏠 *হোম* - আপনি কী করতে চান?",
        "language_title": "🌐 আপনার ভাষা বেছে নিন", "language_current": "বর্তমান ভাষা: {language}",
        "timezone": "সময় অঞ্চল",
        "timezone_title": "🕒 আপনার সময় অঞ্চল বেছে নিন", "timezone_current": "বর্তমান: {zone}",
        "timezone_hint": "নিচে থেকে বেছে নিন, অথবা যেকোনো IANA সময় অঞ্চলের জন্য `/timezone Area/City` পাঠান।",
        "timezone_saved": "সময় অঞ্চল {zone} করা হয়েছে।",
        "timezone_invalid": "সময় অঞ্চলটি চেনা যায়নি। `Asia/Kolkata`-এর মতো নাম ব্যবহার করুন।",
        "welcome": "🚀 *GitHub AI Repo Bot*\n\nTelegram থেকে GitHub রিপোজিটরি পরিচালনা করুন।\n\nGitHub ও AI যুক্ত করতে `/guide` পাঠান। রিপোজিটরি তৈরি বা পরিচালনা করতে মেনু ব্যবহার করুন।",
        "language_saved": "ভাষা {language} করা হয়েছে।", "history_title": "📜 *সাম্প্রতিক কার্যকলাপ*",
        "history_empty": "এখনও কোনো ইতিহাস নেই। এখানে কার্যকলাপ দেখতে প্রথম রিপোজিটরি তৈরি করুন।",
        "history_summary": "মোট {total}টির মধ্যে {start}-{end} - পৃষ্ঠা {page}/{pages}",
        "history_create": "রিপোজিটরি তৈরি", "previous": "◀ আগের", "next": "পরের ▶",
        "models_title": "🤖 *AI প্রদানকারী ও প্রস্তাবিত মডেল*", "free": "বিনামূল্যে", "paid": "পেইড",
        "suggested": "প্রস্তাবিত", "also": "আরও", "set_model": "সেট করুন",
        "status_title": "অ্যাকাউন্টের অবস্থা", "github": "GitHub", "ai_provider": "AI প্রদানকারী",
        "not_set": "সেট করা হয়নি", "token_invalid": "Token অবৈধ বা মেয়াদ শেষ",
        "not_configured": "কনফিগার করা হয়নি", "activity_stats": "কার্যকলাপের পরিসংখ্যান",
        "repos_created": "তৈরি রিপোজিটরি", "repos_deleted": "মুছে ফেলা রিপোজিটরি",
        "repos_cleared": "পরিষ্কার করা রিপোজিটরি",
        "repos_forked": "ফর্ক করা রিপোজিটরি", "repos_starred": "স্টার দেওয়া রিপোজিটরি",
        "archives_uploaded": "আপলোড আর্কাইভ", "files_pushed": "আপলোড ফাইল",
        "contributions": "অবদান", "total_actions": "মোট কাজ", "member_since": "সদস্য হয়েছেন",
        "loaded_in": "লোড হয়েছে",
        "help_text": (
            "🧭 *সাহায্য ও কমান্ড*\n\n*সেটআপ*\n`/start` - প্রধান মেনু খুলুন\n"
            "`/guide` - সেটআপ নির্দেশনা\n`/setgithub` - GitHub যুক্ত করুন\n`/setai` - AI প্রদানকারী বাছুন\n"
            "`/models` - প্রদানকারী ও মডেল দেখুন\n\n*রিপোজিটরি*\n`/create_new_repo` - রিপোজিটরি তৈরি\n"
            "`/suggest` - ধারণা থেকে রিপোজিটরি তৈরি\n`/list_repos` - রিপোজিটরি দেখুন\n"
            "`/import_repo [URL]` - রিপোজিটরি ফর্ক\n`/delete_repo` - রিপোজিটরি মুছুন\n"
            "`/replace_repo` - রিপোজিটরির ফাইল পরিষ্কার করুন (রিপোজিটরি থাকবে)\n"
            "`/star_repo OWNER/REPO` - স্টার দিন\n\n*অ্যাকাউন্ট*\n`/status` - সংযোগ ও কার্যকলাপ\n"
            "`/accounts` - একাধিক GitHub অ্যাকাউন্ট পরিচালনা করুন\n"
            "`/history` - সাম্প্রতিক কার্যকলাপ\n`/support` - সহায়তা নিন"
        ),
        "guide_text": (
            "📖 *দ্রুত সেটআপ নির্দেশিকা*\n\n*1. GitHub যুক্ত করুন*\nGitHub Settings > Developer settings-এ personal access token তৈরি করুন। "
            "প্রয়োজনীয় repository permission দিন; রিপোজিটরি মুছতে delete permission লাগবে।\n"
            "`/setgithub` পাঠিয়ে নির্দেশনা অনুসরণ করুন।\n\n*2. AI যুক্ত করুন (ঐচ্ছিক)*\n"
            "প্রদানকারী দেখতে `/models` চালান। API key তৈরি করে `/setai` চালান।\n\n"
            "*3. রিপোজিটরি তৈরি করুন*\nধাপে ধাপে তৈরি করতে *New Repo* বা ধারণা থেকে শুরু করতে *AI Suggest Repo* বাছুন। "
            "সমর্থিত archive-ও আপলোড করতে পারেন।\n\n*4. সেটআপ দেখুন*\n`/status` সংযোগ দেখায়, `/history` সাম্প্রতিক কাজ দেখায়।\n\n"
            "🔐 Token শুধু এই ব্যক্তিগত চ্যাটে পাঠান। পড়ার পর bot token-এর বার্তা মুছে দেয়।"
        ),
        "admin_help": "\n\n*অ্যাডমিন কমান্ড*\n`/admin` - বট নিয়ন্ত্রণ খুলুন\n`/ban USER_ID` এবং `/unban USER_ID` - প্রবেশাধিকার পরিচালনা\n`/broadcast` - ঘোষণা পাঠান\n`/addadmin USER_ID` এবং `/removeadmin USER_ID` - অ্যাডমিন পরিচালনা",
    },
    "es": {
        "home": "Inicio", "new_repo": "Nuevo repositorio", "ai_suggest": "Idea con IA",
        "archive": "Subir archivo", "fork": "Bifurcar repositorio", "my_repos": "Mis repositorios",
        "edit_repo": "Editar repositorio", "download": "Descargar repositorio", "star": "Marcar con estrella",
        "delete": "Eliminar repositorio", "replace": "Reemplazar repo", "upload_files": "Subir al repo", "live_preview": "Vista previa", "models": "Modelos de IA", "status": "Estado", "accounts": "Mis cuentas", "extras": "Herramientas GitHub",
        "history": "Historial", "help": "Ayuda", "guide": "Guía", "setup": "Configurar", "support": "Soporte",
        "admin": "Panel de administración", "language": "Idioma", "home_title": "🏠 *Inicio* - ¿Qué quieres hacer?",
        "language_title": "🌐 Elige tu idioma", "language_current": "Idioma actual: {language}",
        "timezone": "Zona horaria",
        "timezone_title": "🕒 Elige tu zona horaria", "timezone_current": "Actual: {zone}",
        "timezone_hint": "Elige una zona abajo o envía `/timezone Area/City` para cualquier zona IANA.",
        "timezone_saved": "Zona horaria cambiada a {zone}.",
        "timezone_invalid": "No se reconoce esa zona horaria. Prueba un nombre como `Europe/Madrid`.",
        "welcome": "🚀 *GitHub AI Repo Bot*\n\nAdministra repositorios de GitHub desde Telegram.\n\nEnvía `/guide` para conectar GitHub y un proveedor de IA. Usa el menú para crear o gestionar repositorios.",
        "language_saved": "Idioma cambiado a {language}.", "history_title": "📜 *Actividad reciente*",
        "history_empty": "Aún no hay actividad. Crea tu primer repositorio para verla aquí.",
        "history_summary": "Mostrando {start}-{end} de {total} acciones - Página {page}/{pages}",
        "history_create": "Crear repositorio", "previous": "◀ Anterior", "next": "Siguiente ▶",
        "models_title": "🤖 *Proveedores de IA y modelos sugeridos*", "free": "GRATIS", "paid": "De pago",
        "suggested": "Sugerido", "also": "También", "set_model": "Configurar",
        "status_title": "Estado de la cuenta", "github": "GitHub", "ai_provider": "Proveedor de IA",
        "not_set": "No conectado", "token_invalid": "Token no válido o caducado",
        "not_configured": "No configurado", "activity_stats": "Estadísticas de actividad",
        "repos_created": "Repositorios creados", "repos_deleted": "Repositorios eliminados",
        "repos_cleared": "Repositorios vaciados",
        "repos_forked": "Repositorios bifurcados", "repos_starred": "Repositorios destacados",
        "archives_uploaded": "Archivos subidos", "files_pushed": "Archivos publicados",
        "contributions": "Contribuciones", "total_actions": "acciones en total", "member_since": "Miembro desde",
        "loaded_in": "Cargado en",
        "help_text": (
            "🧭 *Ayuda y comandos*\n\n*Configuración*\n`/start` - Abrir el menú\n"
            "`/guide` - Instrucciones de configuración\n`/setgithub` - Conectar GitHub\n"
            "`/setai` - Elegir proveedor de IA\n`/models` - Ver proveedores y modelos\n\n"
            "*Repositorios*\n`/create_new_repo` - Crear un repositorio\n`/suggest` - Crear desde una idea\n"
            "`/list_repos` - Ver repositorios\n`/import_repo [URL]` - Bifurcar un repositorio\n"
            "`/delete_repo` - Eliminar repositorios\n`/replace_repo` - Vaciar archivos de un repo, sin borrarlo\n"
            "`/star_repo OWNER/REPO` - Marcar con estrella\n\n"
            "*Cuenta*\n`/status` - Revisar conexiones y actividad\n`/accounts` - Gestionar varias cuentas de GitHub\n"
            "`/history` - Ver actividad reciente\n"
            "`/support` - Contactar con soporte"
        ),
        "guide_text": (
            "📖 *Guía rápida de configuración*\n\n*1. Conecta GitHub*\nCrea un token personal en GitHub Settings > Developer settings. "
            "Otorga los permisos necesarios; eliminar repositorios requiere permiso de eliminación.\n"
            "Envía `/setgithub` y sigue las instrucciones.\n\n*2. Conecta IA (opcional)*\n"
            "Ejecuta `/models` para ver proveedores. Crea una clave API y luego ejecuta `/setai`.\n\n"
            "*3. Crea un repositorio*\nUsa *Nuevo repositorio* para hacerlo paso a paso o *Idea con IA* para empezar con una idea. "
            "También puedes subir un archivo compatible.\n\n*4. Revisa la configuración*\n"
            "`/status` muestra las conexiones y `/history` la actividad reciente.\n\n"
            "🔐 Envía tokens solo en este chat privado. El bot elimina el mensaje del token después de leerlo."
        ),
        "admin_help": "\n\n*Comandos de administración*\n`/admin` - Abrir controles del bot\n`/ban USER_ID` y `/unban USER_ID` - Gestionar acceso\n`/broadcast` - Enviar un anuncio\n`/addadmin USER_ID` y `/removeadmin USER_ID` - Gestionar administradores",
    },
}


def normalize_language(code: str | None) -> str:
    """Return a supported base language or English as a safe fallback."""
    base = (code or "en").replace("_", "-").split("-", 1)[0].lower()
    return base if base in LANGUAGES else "en"


def translate(language: str, key: str, /, **values: object) -> str:
    """Translate a UI string, falling back to English for missing entries.

    `language` and `key` are positional-only so template values may legally
    contain keys named `language` or `key` (e.g. the "Current language:
    {language}" template) without colliding with the function parameters.
    """
    template = _TEXT.get(normalize_language(language), _TEXT["en"]).get(key, _TEXT["en"].get(key, key))
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        # A placeholder with no supplied value must never crash a UI screen.
        return template
