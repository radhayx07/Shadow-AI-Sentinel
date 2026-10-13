// Copy the redacted text to the clipboard.
function copyRedacted() {
  const box = document.getElementById("redacted");
  box.select();
  navigator.clipboard.writeText(box.value).then(() => alert("Copied!"));
}
