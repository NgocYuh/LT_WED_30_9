const tokenKey = "jwt-demo-token";

async function readJson(response) {
    const text = await response.text();
    return text ? JSON.parse(text) : {};
}

const loginForm = document.querySelector("#login-form");
if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const response = await fetch("/auth/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                email: document.querySelector("#email").value,
                password: document.querySelector("#password").value
            })
        });
        const body = await readJson(response);
        if (!response.ok) {
            document.querySelector("#message").textContent = body.message || "Đăng nhập thất bại";
            return;
        }
        sessionStorage.setItem(tokenKey, body.token);
        window.location.assign("/user/profile");
    });
}

const profile = document.querySelector("#profile");
if (profile) {
    const token = sessionStorage.getItem(tokenKey);
    if (!token) {
        window.location.replace("/login");
    } else {
        fetch("/users/me", {headers: {Authorization: `Bearer ${token}`}})
            .then(async (response) => {
                const body = await readJson(response);
                if (!response.ok) throw new Error(body.message || "Không thể tải hồ sơ");
                profile.innerHTML = `
                    <dt>Họ tên</dt><dd>${escapeHtml(body.fullName)}</dd>
                    <dt>Email</dt><dd>${escapeHtml(body.email)}</dd>
                    <dt>Vai trò</dt><dd>${escapeHtml(body.role)}</dd>`;
            })
            .catch((error) => {
                sessionStorage.removeItem(tokenKey);
                document.querySelector("#message").textContent = error.message;
                setTimeout(() => window.location.replace("/login"), 1000);
            });
    }
}

document.querySelector("#logout")?.addEventListener("click", () => {
    sessionStorage.removeItem(tokenKey);
    window.location.assign("/login");
});

function escapeHtml(value) {
    const element = document.createElement("div");
    element.textContent = value ?? "";
    return element.innerHTML;
}
