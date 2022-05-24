from datetime import datetime, timezone

HIGH_PRIORITY = "high"
LOW_PRIORITY = "low"

ACTIVE_ALERTS = [
    {
        "id": 1,
        "active": False,
        "priority": HIGH_PRIORITY,
        # yyyy, M,  D,  H,  M,  S, MS
        "timestamp": int((datetime(2022, 5, 23, 0, 0, 0, 0, tzinfo=timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1000),
        "link": "https://google.com",
        "en": {
            "title": "Network Issues",
            "short_description": "Due to ongoing issues with the Nano network, many transactions are delayed.",
            "long_description": "The Nano network is experiencing issues.\n\nSome transactions may be significantly delayed, up to several days. We will keep our users updated with new information as the Nano team provides it.\n\nYou can read more by tapping \"Read More\" below.\n\nAll issues in regards to transaction delays are due to the Nano network issues, not Nautilus. We are not associated with the Nano Foundation or its developers.\n\nWe appreciate your patience during this time."
        },
        "sv": {
            "title": "Nätverksproblem",
            "short_description": "På grund av pågående problem med Nano-nätverket, finns det många fördröjda transaktioner.",
            "long_description": "Nano-nätverket upplever problem som beror på en långvarig och pågående period med spamtransaktioner.\n\nNågra transaktioner kan dröja avsevärt, upp till flera dagar. Vi kommer att hålla våra användare uppdaterade med ny information så snart Nano-teamet förmedlar den.\n\nDu kan läsa mer genom att trycka på \"Läs Mer\" nedan.\n\nAlla problem som rör fördröjda transaktioner är på grund av nätverksproblem hos Nano. Vi är inte associerade med Nano Foundation eller dess utvecklare och kan därför inte påskynda långsamma transaktioner.\n\nVi uppskattar ditt tålamod under denna period.",
        },
        "es": {
            "title": "Problemas de red",
            "short_description": "Debido a problemas continuos con la red Nano, muchas transacciones se retrasan.",
            "long_description": "La red Nano está experimentando problemas causados ​​por un período prolongado y continuo de transacciones de spam.\n\nAlgunas transacciones pueden retrasarse significativamente, hasta varios días. Mantendremos a nuestros usuarios actualizados con nueva información a medida que el equipo de Nano la proporcione.\n\nPuede leer más apretando \"Leer Más\" abajo\n\nTodos los problemas relacionados con las demoras en las transacciones se deben a problemas de la red Nano, no Natrium. No estamos asociados con la Nano Foundation o sus desarrolladores y no podemos hacer nada para acelerar las transacciones lentas.\n\nAgradecemos su paciencia durante este tiempo.",
        },
        "tr": {
            "title": "Ağ Problemleri",
            "short_description": "Nano ağında devam eden spam problemi nedeniyle bir çok işlem gecikmekte.",
            "long_description": "Nano ağı bir süredir devam eden spam nedeniyle problem yaşıyor.\n\nBazı işlemleriniz bir kaç gün süren gecikmelere maruz kalabilir. Nano takımının vereceği güncel haberleri size ileteceğiz.\n\nAşağıdaki \"Detaylı Bilgi\" butonuna dokunarak daha detaylı bilgi alabilirsiniz.\n\nİşlem gecikmeleriyle alakalı bu problemler Natrium'dan değil, Nano ağının kendisinden kaynaklı. Nano Foundation veya geliştiricileriyle bir bağımız olmadığı için işlemlerinizi hızlandırabilmek için şu noktada yapabileceğimiz bir şey ne yazık ki yok.\n\nAnlayışınız ve sabrınız için teşekkür ederiz."
        },
        "ja": {
            "title": "ネットワークエラー",
            "short_description": "Nanoネットワークの継続的な問題により、多くの取引が遅延しています。",
            "long_description": "Nanoネットワークでは、スパムの取引が長期間継続することによって問題が発生しています。\n\n一部の取引は最大数日遅れる場合があります。Nanoチームが提供する新しい情報で、皆さんを最新の状態に保ちます。\n\n 詳しくは\"詳しくは\"ボタンをクリックして下さい。\n\n取引の遅延に関するすべての問題は、Natriumではなく、Nanoネットワークの問題が原因です。NatriumはNano Foundationやその開発者とは関係がなく、遅い取引をスピードアップするために何もすることはできません。\n\nご理解お願いいたします。",
        },
        "de": {
            "title": "Netzwerkprobleme",
            "short_description": "Aufgrund von anhaltenden Problemen mit dem Nano-Netzwerk sind aktuell viele Transaktionen verzögert.",
            "long_description": "Das Nano-Netzwerk kämpft derzeit mit Problemen, die durch eine lang andauernde Serie von Spam-Transaktionen verursacht wurden.\n\nManche Transaktionen können daher stark verzögert sein, teilweise um bis zu mehrere Tage. Wir werden unsere Nutzer über wichtige Neuigkeiten informieren, sobald das Nano-Team diese veröffentlicht.\n\nErfahre mehr, indem du auf \"Mehr Infos\" klickst.\n\nDie Probleme mit verzögerten Transaktionen sind verursacht durch das Nano-Netzwerk, nicht durch Natrium. Wir stehen in keinem Zusammenhang mit der Nano Foundation oder ihren Entwicklern und können daher nichts tun, um die Transaktionen zu beschleunigen.\n\nVielen Dank für dein Verständnis.",
        },
        "fr": {
            "title": "Problèmes de réseau",
            "short_description": "En raison des problèmes en cours avec le réseau Nano, de nombreuses transactions sont retardées.",
            "long_description": "Le réseau Nano connaît des problèmes causés par une période prolongée et continue de transactions de spam.\n\nCertaines transactions peuvent être considérablement retardées, jusqu'à plusieurs jours. Nous tiendrons nos utilisateurs à jour avec de nouvelles informations au fur et à mesure que l'équipe Nano les fournira.\n\nVous pouvez en savoir plus en appuyant sur \"Lire la suite\" ci-dessous.\n\nTous les problèmes liés aux retards de transaction sont dus aux problèmes de réseau Nano, et non à Natrium. Nous ne sommes pas associés à la Fondation Nano ou à ses développeurs et ne pouvons rien faire pour accélérer les transactions lentes.\n\nNous apprécions votre patience pendant cette période.",
        },
        "nl": {
            "title": "Netwerkproblemen",
            "short_description": "Door aanhoudende problemen met het Nano-netwerk lopen veel transacties vertraging op.",
            "long_description": "Het Nano-netwerk ondervindt problemen die worden veroorzaakt door een langdurige, aanhoudende periode van spamtransacties.\n\nSommige transacties kunnen aanzienlijk worden vertraagd, tot enkele dagen. We houden onze gebruikers op de hoogte van nieuwe informatie zodra het Nano-team dit communiceert.\n\nJe kan meer lezen door hieronder op \"Meer lezen\" te klikken.\n\nAlle problemen met betrekking tot transactievertragingen zijn te wijten aan problemen met het Nano-netwerk, niet aan Natrium. We zijn niet geassocieerd met de Nano Foundation of hun ontwikkelaars en kunnen niets doen om langzame transacties te versnellen.\n\nWe stellen jouw geduld gedurende deze tijd op prijs.",
        },
        "iDD": {
            "title": "Masalah Jaringan",
            "short_description": "Karena masalah yang sedang berlangsung dengan jaringan Nano, banyak transaksi yang tertunda.",
            "long_description": "Jaringan Nano mengalami masalah yang disebabkan oleh periode transaksi spam yang berkepanjangan dan berkelanjutan.\n\nBeberapa transaksi mungkin tertunda secara signifikan, hingga beberapa hari. Kami akan terus memperbarui informasi baru kepada pengguna kami saat tim Nano menyediakannya.\n\nAnda dapat membaca selengkapnya dengan mengetuk \"Baca Selengkapnya\" di bawah.\n\nSemua masalah terkait penundaan transaksi disebabkan oleh masalah jaringan Nano, bukan Natrium. Kami tidak terkait dengan Nano Foundation atau pengembangnya dan tidak dapat melakukan apa pun untuk mempercepat transaksi yang lambat.\n\nKami menghargai kesabaran anda selama ini.",
        },
        "ru": {
            "title": "Проблемы с сетью",
            "short_description": "Из-за текущих проблем с сетью Nano многие транзакции задерживаются.",
            "long_description": "В сети Nano возникают проблемы, вызванные продолжительным периодом спам-транзакций.\n\nНекоторые транзакции могут быть значительно задержаны, до нескольких дней. Мы будем держать наших пользователей в курсе новой информации, поскольку команда Nano  предоставляет его.\n\nВы можете узнать больше, нажав \"Подробнее\" ниже.\n\nВсе проблемы, связанные с задержками транзакций, вызваны проблемами сети Nano, а не Natrium. Мы не связаны с Nano Foundation его разработчики не могут ничего сделать для ускорения медленных  транзакций.\n\nМы благодарим вас за терпение в это время.",
        },
        "da": {
            "title": "Netværksproblemer",
            "short_description": "På grund af igangværende problemer med Nano-netværket er der mange forsinkede transaktioner.",
            "long_description": "Nano-netværket oplever problemer på grund af en lang og løbende periode med spamtransaktioner.\n\nNogle transaktioner kan tage lang tid, op til flere dage. Vi holder vores brugere opdateret med nye oplysninger, så snart Nano-teamet giver dem.\n\nDu kan læse mere ved at klikke \"Læs mere\" nedenfor.\n\nAlle problemer med hensyn til transaktionsforsinkelser skyldes problemer med Nano-netværket, ikke Natrium. Vi er ikke tilknyttet Nano Foundation eller dets udviklere og kan ikke gøre noget for at fremskynde langsomme transaktioner.\n\nVi sætter pris på din tålmodighed i denne periode.",
        }
    }
]


def get_active_alert(lang: str):
    ret = []
    for a in ACTIVE_ALERTS:
        active = a["active"]
        if active:
            if lang == 'id' and 'iDD' in a:
                lang = 'iDD'
            elif lang not in a:
                lang = 'en'
            retItem = {
                "id": a["id"],
                "priority": a["priority"],
                "active": a["active"],
            }
            if "timestamp" in a:
                retItem["timestamp"] = a["timestamp"]
            if "link" in a:
                retItem["link"] = a["link"]
            for k, v in a[lang].items():
                retItem[k] = v
            ret.append(retItem)

    return ret
