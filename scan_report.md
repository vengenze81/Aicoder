# Security Reconnaissance Report

- **Target:** `https://medistore.se`
- **Timestamp:** `2026-09-17 12:10:37`
- **Total Findings:** `31`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/hjalpmedel/smarta-enkla-verktyg/griptaang/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/hjalpmedel/smarta-enkla-verktyg/griptaang/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/sjukvardsinredning/skaalar/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/sjukvardsinredning/skaalar/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/rehab-sjukgymnastik/sporttejp/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/rehab-sjukgymnastik/sporttejp/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/valbefinnande/varmekudde/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/valbefinnande/varmekudde/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/hygien/damskydd/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/hygien/damskydd/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/medicinsk-utrustning/blodtrycksmatare/manuella-blodtrycksmatare/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/medicinsk-utrustning/blodtrycksmatare/manuella-blodtrycksmatare/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/kopvillkor/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/kopvillkor/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/ortos/fotprodukter/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/ortos/fotprodukter/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/valbefinnande/varmekudde/?add-to-cart=5208 [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/egenvard/valbefinnande/varmekudde/?add-to-cart=5208 [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/hygien/handskar/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/hygien/handskar/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/ [Method: POST, Inputs: ['quantity', 'add-to-cart', 'product_id', 'variation_id']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/andningshjalpmedel/nasgrimma/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/sjukvard/andningshjalpmedel/nasgrimma/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/hjalpmedel/inkontinensprodukter/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler | **LOW** | Discovered HTML Form on https://medistore.se/category/hjalpmedel/inkontinensprodukter/ [Method: GET, Inputs: ['s', 'post_type']] |
| Web Crawler Attack Surface Analysis | **INFO** | Analyzed data successfully logged. |

## Detailed Module Sections

### Web Crawler Attack Surface Analysis
```json
{
  "pages_visited": 15,
  "total_links": 44,
  "forms_discovered": 31,
  "findings": [
    {
      "type": "link",
      "url": "https://medistore.se/category/medicinsk-utrustning/blodtrycksmatare/manuella-blodtrycksmatare/?add-to-cart=1444"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/sjukvard/andningshjalpmedel/nasgrimma/?add-to-cart=4413"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/medicinsk-utrustning/blodkoaguleringstest/"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/egenvard/ortos/fotprodukter/?add-to-cart=5430"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/hjalpmedel/smarta-enkla-verktyg/griptaang/"
    },
    {
      "type": "link",
      "url": "https://medistore.se/product/returetikett-dhl-4-20kg/"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/sjukvard/sjukvardsinredning/skaalar/"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/sjukvard/hygien/damskydd/#content"
    },
    {
      "type": "link",
      "url": "https://medistore.se/valj-storlek/s-6-7/"
    },
    {
      "type": "link",
      "url": "https://medistore.se/category/rehab-sjukgymnastik/sporttejp/"
    },
    {
      "type": "form",
      "page": "https://medistore.se",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/hjalpmedel/smarta-enkla-verktyg/griptaang/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/hjalpmedel/smarta-enkla-verktyg/griptaang/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/sjukvardsinredning/skaalar/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/sjukvardsinredning/skaalar/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/rehab-sjukgymnastik/sporttejp/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/rehab-sjukgymnastik/sporttejp/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/valbefinnande/varmekudde/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/valbefinnande/varmekudde/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/hygien/damskydd/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/hygien/damskydd/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/medicinsk-utrustning/blodtrycksmatare/manuella-blodtrycksmatare/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/medicinsk-utrustning/blodtrycksmatare/manuella-blodtrycksmatare/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/kopvillkor/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/kopvillkor/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/ortos/fotprodukter/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/ortos/fotprodukter/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/valbefinnande/varmekudde/?add-to-cart=5208",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/egenvard/valbefinnande/varmekudde/?add-to-cart=5208",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/hygien/handskar/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/hygien/handskar/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/product/engaangshandske-vinyl-ftalatfri-puderfri/",
      "inputs": [
        "quantity",
        "add-to-cart",
        "product_id",
        "variation_id"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/andningshjalpmedel/nasgrimma/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/sjukvard/andningshjalpmedel/nasgrimma/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/hjalpmedel/inkontinensprodukter/",
      "inputs": [
        "s",
        "post_type"
      ]
    },
    {
      "type": "form",
      "page": "https://medistore.se/category/hjalpmedel/inkontinensprodukter/",
      "inputs": [
        "s",
        "post_type"
      ]
    }
  ]
}
```
