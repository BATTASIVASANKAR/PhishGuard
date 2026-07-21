"""
PhishGuard - ML Model Training Script
Trains a Random Forest classifier on URL features for phishing detection.
Outputs model.pkl for use in the Flask app.
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# ── Feature extraction helpers ──────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm',
    'password', 'signin', 'credential', 'suspend', 'alert', 'expire',
    'unusual', 'restrict', 'wallet', 'paypal', 'ebay', 'apple', 'microsoft'
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy'
]


def extract_features(url: str) -> list:
    """Extract numeric features from a URL string."""
    url_lower = url.lower()

    features = [
        len(url),                                       # 0: length
        url_lower.count('.'),                           # 1: dot count
        url_lower.count('-'),                           # 2: dash count
        url_lower.count('@'),                           # 3: @ symbol
        url_lower.count('//'),                          # 4: double-slash count
        1 if 'https' in url_lower else 0,               # 5: has https
        1 if any(c.isdigit() for c in url_lower.split('/')[2] if '/' in url_lower) else 0,  # 6: digits in domain
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),  # 7: suspicious keywords
        1 if any(sd in url_lower for sd in SHORTENER_DOMAINS) else 0,  # 8: shortener
        url_lower.count('/'),                           # 9: slash count
        url_lower.count('?'),                           # 10: query params
        url_lower.count('='),                           # 11: equals signs
        len(url_lower.split('/')[2]) if len(url_lower.split('/')) > 2 else len(url_lower),  # 12: domain length
        1 if url_lower.count('.') > 4 else 0,           # 13: many subdomains
    ]
    return features


# ── Synthetic training data ──────────────────────────────────────────────────

SAFE_URLS = [
    'https://www.google.com',
    'https://www.github.com',
    'https://www.stackoverflow.com/questions',
    'https://www.wikipedia.org/wiki/Python',
    'https://www.youtube.com/watch?v=abc123',
    'https://www.amazon.com/dp/B08N5WRWNW',
    'https://docs.python.org/3/library/pickle.html',
    'https://www.reddit.com/r/programming',
    'https://www.bbc.com/news',
    'https://www.nytimes.com/section/technology',
    'https://www.linkedin.com/in/johndoe',
    'https://www.twitter.com/elonmusk',
    'https://www.microsoft.com/en-us/windows',
    'https://www.apple.com/iphone',
    'https://www.netflix.com/browse',
    'https://www.spotify.com/us/premium',
    'https://www.dropbox.com/home',
    'https://www.medium.com/technology',
    'https://www.coursera.org/learn/machine-learning',
    'https://www.kaggle.com/datasets',
    'https://www.npmjs.com/package/express',
    'https://www.cloudflare.com',
    'https://www.heroku.com',
    'https://www.digitalocean.com',
    'https://www.mozilla.org/en-US/firefox',
    'https://www.adobe.com/products/photoshop',
    'https://www.slack.com',
    'https://www.notion.so',
    'https://www.figma.com',
    'https://www.canva.com',
    'https://www.twitch.tv',
    'https://www.paypal.com',
    'https://www.stripe.com/docs',
    'https://www.elastic.co/elasticsearch',
    'https://www.docker.com/get-started',
    'https://www.kubernetes.io/docs',
    'https://www.postgresql.org/docs',
    'https://www.mongodb.com',
    'https://www.rust-lang.org',
    'https://www.golang.org',
]

PHISHING_URLS = [
    'http://192.168.1.1/login/verify-account',
    'http://secure-login-update.verify-account-now.com/signin',
    'http://bit.ly/3xYz123',
    'http://www.g00gle.com/accounts/login',
    'http://paypal-secure-update.com/confirm-password',
    'http://apple-id-verify.suspicious-domain.com/credential',
    'http://login.microsoft-alert.com/suspend/account',
    'http://www.bank-secure-login.com/update/verify',
    'http://192.168.0.1:8080/admin/login',
    'http://ebay-unusual-activity-alert.com/verify',
    'http://account-restricted-paypal.com/wallet/secure',
    'http://www.verify-your-account-now.com/login.php?id=12345',
    'http://tinyurl.com/phish123',
    'http://signin-apple-id.com/password/reset',
    'http://microsoft-expire-alert.com/confirm',
    'http://login-verify-secure.com/account/update/bank',
    'http://www.suspicious.site.with.many.dots.com/login',
    'http://192.168.1.100/secure/bank/login/verify',
    'http://credential-update@suspicious-site.com/login',
    'http://www.free-prize-winner-claim.com/verify?user=12345&token=abc',
    'http://update-your-password-now.com/secure/login',
    'http://www.bank-of-america-secure.verify-now.com/login',
    'http://adf.ly/redirect-login',
    'http://signin.account.verify-credential-expire.com',
    'http://wallet-paypal-secure.com/unusual-activity',
    'http://192.168.2.50/login.php?redirect=http://evil.com',
    'http://www.click-here-to-verify.com/account/suspend',
    'http://login.fake-microsoft.com/password/credential',
    'http://secure-ebay-alert.com/restrict/account',
    'http://www.verify-apple-id-now.com/signin/update',
    'http://cutt.ly/susp1c10us',
    'http://192.168.0.5/bank/credential/verify/secure',
    'http://confirm-paypal-account.com/wallet',
    'http://www.expire-alert-microsoft.com/login/update',
    'http://suspicious-update.com/password/bank/login/verify/secure',
    'http://goo.gl/ph1sh',
    'http://account.alert.verify.login.suspicious.com/update',
    'http://www.apple-credential-expire.com/signin',
    'http://verify-bank-login.com/account/secure/update/confirm',
    'http://192.168.3.200/admin/login/bank/verify',
]

# ── Train model ──────────────────────────────────────────────────────────────

def main():
    # Build feature matrix
    X = []
    y = []

    for url in SAFE_URLS:
        X.append(extract_features(url))
        y.append(0)  # safe

    for url in PHISHING_URLS:
        X.append(extract_features(url))
        y.append(1)  # phishing

    X = np.array(X)
    y = np.array(y)

    # Add noise-augmented samples for robustness
    rng = np.random.RandomState(42)
    X_aug = X + rng.normal(0, 0.5, X.shape)
    X_full = np.vstack([X, X_aug])
    y_full = np.hstack([y, y])

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_full, y_full)

    # Evaluate on training data (sanity check)
    acc = model.score(X, y)
    print(f"Training accuracy: {acc:.2%}")

    # Save model
    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print("Model saved to model.pkl")


if __name__ == '__main__':
    main()
