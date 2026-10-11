"""Original 5 verification checks (preserved)."""
import sys, dlp_engine as E
def t(name,ok): print(("PASS" if ok else "FAIL"),"-",name); return ok
r=[t("Aadhaar checksum validation",E.verhoeff(E._demo_aadhaar()) and not E.verhoeff("234567890124" if E._demo_aadhaar()!="234567890124" else "234567890123")),
   t("Payment card checksum validation",E.luhn("4111111111111111") and not E.luhn("4111111111111112")),
   t("All five categories detected",{i["type"] for i in E.scan_text(E.SAMPLE)}=={"Payment Card","Aadhaar","PAN","Phone (IN)","Email"}),
   t("Invalid-checksum card rejected",not E.scan_text("card 4111 1111 1111 1112")),
   t("Ordinary text -> zero incidents",E.scan_text("Meeting at 10am, order 42 shipped. Thanks!")==[])]
sys.exit(0 if all(r) else 1)
