# Image credits and licenses

All images were downloaded from Wikimedia Commons on 2026-07-23. Licenses were
verified programmatically via the Commons API
(`https://commons.wikimedia.org/w/api.php?action=query&prop=imageinfo&iiprop=extmetadata`,
field `LicenseShortName` / `LicenseUrl` / `Copyrighted`) and cross-checked
against each file's description page.

| File | Source | Author | License | Verification |
| --- | --- | --- | --- | --- |
| `vault-door.jpg` | [Porta caveau banca - Bank vault door - 1967.png](https://commons.wikimedia.org/wiki/File:Porta_caveau_banca_-_Bank_vault_door_-_1967.png) | Aldo Moisio | Public domain (Italian simple photograph, copyright expired) | API extmetadata: `LicenseShortName = Public domain`, `Copyrighted = False` |
| `press-room.jpg` | [Newspaper publishing - N.Y. Herald - Corner of press room (LCCN 2004670982)](https://commons.wikimedia.org/wiki/File:Newspaper_publishing_-_N.Y._Herald-_Corner_of_press_room_LCCN2004670982.jpg) | George Grantham Bain Collection, Library of Congress ([lccn.loc.gov/2004670982](https://lccn.loc.gov/2004670982)) | Public domain (LoC Bain Collection — no known restrictions) | API extmetadata: `LicenseShortName = Public domain`, `Copyrighted = False` |
| `empty-desks.jpg` | [Rows of Desks in Lecture Theatre.jpg](https://commons.wikimedia.org/wiki/File:Rows_of_Desks_in_Lecture_Theatre.jpg) | Paul The Writer | CC0 1.0 (public-domain dedication) | API extmetadata: `LicenseShortName = CC0`, `LicenseUrl = creativecommons.org/publicdomain/zero/1.0` |
| `antenna-dish.jpg` | [Canberra Deep Dish Communications Complex - GPN-2000-000502.jpg](https://commons.wikimedia.org/wiki/File:Canberra_Deep_Dish_Communications_Complex_-_GPN-2000-000502.jpg) | NASA (Great Images in NASA) | Public domain (NASA work) | API extmetadata: `LicenseShortName = Public domain`, `Copyrighted = False` |
| `fingerprint-card.jpg` | [Al Capone's fingerprint card.jpg](https://commons.wikimedia.org/wiki/File:Al_Capone%27s_fingerprint_card.jpg) | FBI (Federal Bureau of Investigation) | Public domain (US federal government work) | API extmetadata: `LicenseShortName = Public domain`, `Copyrighted = False` |
| `exam-hall.jpg` | [Exam hall.jpg](https://commons.wikimedia.org/wiki/File:Exam_hall.jpg) | Homayoon soleimani | CC0 1.0 (public-domain dedication) | API extmetadata: `LicenseShortName = CC0`, `LicenseUrl = creativecommons.org/publicdomain/zero/1.0` |

Notes:

- Each file was downloaded as a 1280px-wide Wikimedia thumbnail to keep sizes
  small (all under 1 MB).
- `vault-door.jpg` was converted from the original PNG to JPEG locally
  (`sips -s format jpeg`); no other edits were made.
- CC0 and public-domain works require no attribution; authors are credited
  above and in the presentation as a courtesy.
