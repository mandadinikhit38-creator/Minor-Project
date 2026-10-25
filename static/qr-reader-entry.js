import jsQR from "jsqr";
import QRCode from "qrcode";

window.phishlensQr = {
  decode(data, width, height) {
    return jsQR(data, width, height, { inversionAttempts: "attemptBoth" });
  },
  generate(value) {
    return QRCode.toDataURL(value, {
      errorCorrectionLevel: "M",
      margin: 4,
      width: 400,
      color: { dark: "#000000", light: "#FFFFFF" },
    });
  },
};
