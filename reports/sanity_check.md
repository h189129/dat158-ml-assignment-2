# Kvalitativ sjekk av modell v2

## Skjult liste (frosset før v2-iterasjonen, kjørt etter at v2 var låst, aldri brukt til tuning)

| Type | URL | Bånd | Score |
|---|---|---|---|
| Legitim | `https://www[.]dagbladet[.]no/` | Lav risiko | 9 |
| Legitim | `https://www[.]e24[.]no/` | Mistenkelig | 27 |
| Legitim | `https://www[.]bt[.]no/` | Lav risiko | 4 |
| Legitim | `https://www[.]tv2[.]no/nyheter` | Høy risiko | 71 |
| Legitim | `https://www[.]nordea[.]no/privat/` | Lav risiko | 11 |
| Legitim | `https://www[.]storebrand[.]no/` | Lav risiko | 8 |
| Legitim | `https://www[.]gjensidige[.]no/privat/forsikring` | Lav risiko | 2 |
| Legitim | `https://www[.]if[.]no/` | Lav risiko | 2 |
| Legitim | `https://www[.]lanekassen[.]no/` | Lav risiko | 8 |
| Legitim | `https://www[.]udir[.]no/` | Lav risiko | 4 |
| Legitim | `https://www[.]ntnu[.]no/studier` | Mistenkelig | 15 |
| Legitim | `https://www[.]uio[.]no/` | Lav risiko | 1 |
| Legitim | `https://www[.]oslo[.]kommune[.]no/` | Lav risiko | 0 |
| Legitim | `https://www[.]bergen[.]kommune[.]no/` | Lav risiko | 0 |
| Legitim | `https://www[.]politiet[.]no/` | Lav risiko | 9 |
| Legitim | `https://www[.]brreg[.]no/` | Mistenkelig | 15 |
| Legitim | `https://www[.]statensvegvesen[.]no/` | Lav risiko | 8 |
| Legitim | `https://www[.]xxl[.]no/` | Lav risiko | 3 |
| Legitim | `https://www[.]power[.]no/` | Lav risiko | 6 |
| Legitim | `https://www[.]zalando[.]no/` | Lav risiko | 7 |
| Legitim | `https://www[.]kiwi[.]no/` | Lav risiko | 2 |
| Legitim | `https://www[.]obos[.]no/` | Lav risiko | 1 |
| Legitim | `https://www[.]prisjakt[.]no/` | Mistenkelig | 16 |
| Legitim | `https://www[.]sas[.]no/` | Lav risiko | 1 |
| Legitim | `https://www[.]flytoget[.]no/` | Mistenkelig | 14 |
| Legitim | `https://www[.]ikea[.]com/no/no/` | Lav risiko | 0 |
| Legitim | `https://www[.]spotify[.]com/no/` | Lav risiko | 0 |
| Legitim | `https://www[.]microsoft[.]com/nb-no/` | Lav risiko | 0 |
| Legitim | `https://www[.]apple[.]com/no/` | Lav risiko | 0 |
| Legitim | `https://www[.]netflix[.]com/no/` | Lav risiko | 0 |
| Konstruert phishing | `https://nordea-kunde-verifisering[.]top/login` | Høy risiko | 99 |
| Konstruert phishing | `http://bankid-fornyelse[.]info/oppdater` | Høy risiko | 96 |
| Konstruert phishing | `https://lanekassen-tilbakebetaling[.]click/refund` | Høy risiko | 99 |
| Konstruert phishing | `https://gjensidige[.]no[.]claim-payment[.]xyz/` | Høy risiko | 92 |
| Konstruert phishing | `http://45[.]13[.]22[.]101/storebrand/secure/login[.]php` | Høy risiko | 99 |
| Konstruert phishing | `https://politiet-bot-betaling[.]shop/` | Høy risiko | 97 |
| Konstruert phishing | `https://netflix-account-suspended[.]vercel[.]app/update` | Høy risiko | 99 |
| Konstruert phishing | `https://apple-icloud-locked[.]web[.]app/unlock` | Høy risiko | 99 |
| Konstruert phishing | `https://xn--nrdea-ppa[.]com/login` | Høy risiko | 80 |
| Konstruert phishing | `https://postnord-pakke-toll[.]buzz/betal` | Høy risiko | 94 |

## Utviklingsliste (avdekket merkenavn-feilen i v1, har derfor påvirket utviklingen)

| Type | URL | Bånd | Score |
|---|---|---|---|
| Legitim | `https://www[.]nrk[.]no` | Lav risiko | 3 |
| Legitim | `https://www[.]nrk[.]no/nyheter/` | Mistenkelig | 13 |
| Legitim | `https://www[.]vg[.]no` | Lav risiko | 4 |
| Legitim | `https://www[.]vg[.]no/nyheter` | Mistenkelig | 16 |
| Legitim | `https://www[.]aftenposten[.]no/` | Lav risiko | 8 |
| Legitim | `https://www[.]dnb[.]no/` | Lav risiko | 1 |
| Legitim | `https://www[.]dnb[.]no/privat/kort` | Lav risiko | 0 |
| Legitim | `https://www[.]vipps[.]no/` | Lav risiko | 8 |
| Legitim | `https://www[.]posten[.]no/sporing` | Lav risiko | 1 |
| Legitim | `https://www[.]nav[.]no/` | Lav risiko | 1 |
| Legitim | `https://www[.]skatteetaten[.]no/person/skatt/` | Lav risiko | 6 |
| Legitim | `https://www[.]hvl[.]no/` | Lav risiko | 4 |
| Legitim | `https://www[.]hvl[.]no/studier/` | Mistenkelig | 17 |
| Legitim | `https://www[.]uib[.]no/` | Lav risiko | 2 |
| Legitim | `https://www[.]finn[.]no/` | Lav risiko | 2 |
| Legitim | `https://www[.]finn[.]no/bap/forsale/search[.]html` | Mistenkelig | 32 |
| Legitim | `https://www[.]regjeringen[.]no/no/id4/` | Mistenkelig | 22 |
| Legitim | `https://www[.]helsenorge[.]no/` | Lav risiko | 9 |
| Legitim | `https://www[.]yr[.]no/nb` | Lav risiko | 7 |
| Legitim | `https://www[.]altinn[.]no/` | Lav risiko | 6 |
| Legitim | `https://www[.]bankid[.]no/` | Lav risiko | 3 |
| Legitim | `https://www[.]elkjop[.]no/` | Lav risiko | 7 |
| Legitim | `https://www[.]komplett[.]no/` | Mistenkelig | 14 |
| Legitim | `https://www[.]sparebank1[.]no/nb/bank/privat[.]html` | Mistenkelig | 47 |
| Legitim | `https://www[.]telenor[.]no/` | Lav risiko | 7 |
| Legitim | `https://www[.]ruter[.]no/` | Lav risiko | 6 |
| Legitim | `https://www[.]vy[.]no/` | Lav risiko | 4 |
| Legitim | `https://www[.]norwegian[.]no/` | Lav risiko | 9 |
| Legitim | `https://www[.]husqvarna[.]com/no/` | Lav risiko | 2 |
| Legitim | `https://github[.]com/` | Lav risiko | 3 |
| Konstruert phishing | `http://secure-dnb-login[.]verify-account[.]xyz/bankid` | Høy risiko | 99 |
| Konstruert phishing | `https://vipps-refund-claim[.]webflow[.]io/` | Høy risiko | 99 |
| Konstruert phishing | `http://192[.]168[.]10[.]5/posten/tracking[.]php` | Høy risiko | 99 |
| Konstruert phishing | `https://posten-no-sporing-pakke[.]top/betal` | Høy risiko | 99 |
| Konstruert phishing | `https://nav-utbetaling-bekreft[.]com/login` | Høy risiko | 95 |
| Konstruert phishing | `https://dnb[.]no[.]secure-auth-session[.]click/` | Høy risiko | 99 |
| Konstruert phishing | `https://xn--pypal-4ve[.]com/signin` | Mistenkelig | 50 |
| Konstruert phishing | `http://apple-id-unlock-support[.]info/account/verify` | Høy risiko | 99 |
| Konstruert phishing | `https://helsenorge-innlogging[.]shop/bankid` | Høy risiko | 99 |
| Konstruert phishing | `https://microsoft365-mailbox-upgrade[.]vercel[.]app/` | Høy risiko | 99 |
