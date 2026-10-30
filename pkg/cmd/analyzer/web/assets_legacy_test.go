// spaHTML is the single seam every UI test goes through. It returns the full
// reassembled page (markup with the stylesheet and script inlined), exactly
// what the old webUIHTML const held: the CSS/JS assertions need the real
// content, and pointing it at bare index.html would let them pass vacuously.

package web

func spaHTML() string {
	return webUIHTML
}

// webUIHTML reassembles the old single-string form for tests that assert across
// the <style>/<script> boundary. Test-only: it exists in test builds alone.
var webUIHTML = func() string {
	h := mustAsset("assets/index.html")
	h = replaceOnce(h, `<link rel="stylesheet" href="/static/app.css">`,
		"<style>\n"+mustAsset("assets/app.css")+"</style>")
	h = replaceOnce(h, `<script src="/static/app.js" defer></script>`,
		"<script>\n"+mustAsset("assets/app.js")+"</script>")
	return h
}()

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		panic("webui: asset seam not found: " + old)
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
