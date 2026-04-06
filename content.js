function getInteractiveTarget(startNode) {
  if (!(startNode instanceof Element)) {
    return null;
  }

  return startNode.closest(
    'a[href], button, [role="button"], input[type="submit"], input[type="button"]'
  );
}

function notifyUserInteraction() {
  try {
    const runtime = globalThis.chrome?.runtime;
    if (!runtime || typeof runtime.sendMessage !== "function") {
      return;
    }

    runtime.sendMessage({ type: "userInteraction" }, () => {
      // Touch lastError to suppress unchecked runtime messaging errors.
      void globalThis.chrome?.runtime?.lastError;
    });
  } catch {
    // Ignore invalidated extension contexts.
  }
}

document.addEventListener(
  "click",
  (event) => {
    try {
      const target = getInteractiveTarget(event.target);
      if (!target) {
        return;
      }

      notifyUserInteraction();
    } catch {
      // Ignore invalidated extension contexts.
    }
  },
  true
);
