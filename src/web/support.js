  const toast = document.getElementById("toast");
  let toastT;
  function showToast(msg){
    toast.textContent = msg;
    toast.classList.add("show");
    clearTimeout(toastT);
    toastT = setTimeout(()=>toast.classList.remove("show"), 1600);
  }
  document.querySelectorAll(".btn.copy").forEach(b => {
    b.addEventListener("click", async () => {
      const v = b.getAttribute("data-val") || "";
      try { await navigator.clipboard.writeText(v); showToast("Copied to clipboard ✓"); }
      catch(e){
        // Fallback for insecure contexts / older browsers.
        const t = document.createElement("textarea");
        t.value = v; t.style.position = "fixed"; t.style.opacity = "0";
        document.body.appendChild(t); t.select();
        try { document.execCommand("copy"); showToast("Copied ✓"); } catch(_){ showToast("Copy failed"); }
        document.body.removeChild(t);
      }
    });
  });