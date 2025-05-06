from flask import Flask, render_template, request, jsonify
import pickle
import re
import numpy as np
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# Load the trained model and scaler
with open('phishing_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('scaler.pkl', 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)

# Feature extraction functions
def extract_url_features(url):
    features = {}
    
    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
    except:
        return None
    
    # 1. URL-based features
    features['length_url'] = len(url)
    features['length_hostname'] = len(domain)
    features['ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_slash'] = url.count('/')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www' in domain.lower() else 0
    features['nb_com'] = 1 if domain.endswith('.com') else 0
    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if parsed.scheme == 'https' else 0
    
    # 2. Domain-based features
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    features['tld_in_path'] = 1 if any(tld in path.lower() for tld in ['.com', '.net', '.org']) else 0
    features['tld_in_subdomain'] = 1 if any(tld in domain.lower() for tld in ['.com', '.net', '.org']) else 0
    features['abnormal_subdomain'] = 1 if len(domain.split('.')) > 3 else 0
    features['nb_subdomains'] = len(domain.split('.')) - 1
    features['prefix_suffix'] = 1 if '-' in domain else 0
    features['random_domain'] = 1 if re.search(r'[0-9a-f]{8}', domain) else 0  # Check for random-looking strings
    
    # 3. Path-based features
    path_words = re.findall(r'[a-zA-Z]+', path)
    features['length_words_raw'] = len(path_words)
    features['shortest_words_raw'] = len(min(path_words, key=len)) if path_words else 0
    features['shortest_word_path'] = features['shortest_words_raw']
    features['longest_words_raw'] = len(max(path_words, key=len)) if path_words else 0
    features['longest_word_path'] = features['longest_words_raw']
    features['avg_words_raw'] = sum(len(word) for word in path_words)/len(path_words) if path_words else 0
    features['avg_word_path'] = features['avg_words_raw']
    
    # 4. Other features (simplified for demo)
    features['phish_hints'] = sum(1 for word in ['login', 'secure', 'account', 'bank', 'verify'] if word in url.lower())
    features['domain_in_brand'] = 0  # Would need brand list to check
    features['brand_in_subdomain'] = 0  # Would need brand list to check
    features['brand_in_path'] = 0  # Would need brand list to check
    features['suspecious_tld'] = 1 if domain.endswith(('.tk', '.gq', '.ml', '.cf', '.ga')) else 0
    
    # 5. Set default values for features we can't extract from URL alone
    features['statistical_report'] = 0
    features['nb_hyperlinks'] = 0
    features['ratio_intHyperlinks'] = 0
    features['ratio_extHyperlinks'] = 0
    features['ratio_nullHyperlinks'] = 0
    features['nb_extCSS'] = 0
    features['ratio_intRedirection'] = 0
    features['ratio_extRedirection'] = 0
    features['ratio_intErrors'] = 0
    features['ratio_extErrors'] = 0
    features['login_form'] = 1 if any(word in url.lower() for word in ['login', 'signin']) else 0
    features['external_favicon'] = 0
    features['links_in_tags'] = 0
    features['submit_email'] = 1 if 'email' in url.lower() else 0
    features['ratio_intMedia'] = 0
    features['ratio_extMedia'] = 0
    features['sfh'] = 0
    features['iframe'] = 0
    features['popup_window'] = 0
    features['safe_anchor'] = 0
    features['onmouseover'] = 0
    features['right_clic'] = 0
    features['empty_title'] = 0
    features['domain_in_title'] = 0
    features['domain_with_copyright'] = 0
    features['whois_registered_domain'] = 0
    features['domain_registration_length'] = 365  # Assume 1 year
    features['domain_age'] = 365  # Assume 1 year
    features['web_traffic'] = 0
    features['dns_record'] = 1  # Assume valid DNS
    features['google_index'] = 1  # Assume indexed
    features['page_rank'] = 3  # Medium rank
    
    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
    
    # Validate URL format
    if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
        return jsonify({'error': 'Invalid URL format. Please include http:// or https://'}), 400
    
    # Extract features
    features = extract_url_features(url)
    if features is None:
        return jsonify({'error': 'Could not parse URL'}), 400
    
    # Prepare features in correct order for model
    feature_order = [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 
        'nb_and', 'nb_eq', 'nb_underscore', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
        'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash',
        'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode',
        'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
        'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension',
        'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat',
        'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
        'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host',
        'avg_word_path', 'phish_hints', 'domain_in_brand', 'brand_in_subdomain',
        'brand_in_path', 'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
        'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
        'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
        'login_form', 'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia',
        'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
        'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
        'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic',
        'dns_record', 'google_index', 'page_rank'
    ]
    
    # Fill in any missing features with 0
    feature_values = [features.get(feat, 0) for feat in feature_order]
    
    # Scale features and make prediction
    try:
        scaled_features = scaler.transform(np.array(feature_values).reshape(1, -1))
        prediction = model.predict(scaled_features)[0]
        probability = model.predict_proba(scaled_features)[0][1]
    except Exception as e:
        return jsonify({'error': 'Error processing URL', 'details': str(e)}), 500
    
    # Get top 5 most suspicious features
    feature_importances = model.feature_importances_ if hasattr(model, 'feature_importances_') else None
    suspicious_features = []
    
    if feature_importances is not None:
        top_indices = np.argsort(feature_importances)[::-1][:5]
        suspicious_features = [
            {'feature': feature_order[i], 'value': feature_values[i], 'importance': feature_importances[i]}
            for i in top_indices
        ]
    
    return jsonify({
        'url': url,
        'is_phishing': bool(prediction),
        'probability': float(probability),
        'suspicious_features': suspicious
        _features,
        'all_features': features
    })

if __name__ == '__main__':
    app.run(debug=True)