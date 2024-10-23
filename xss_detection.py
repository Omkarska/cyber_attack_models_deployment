import pickle
from urllib.parse import unquote

# Load the XSS model (Random Forest Classifier)
try:
    with open('RandomForestClassifier.sav', 'rb') as model_file:
        xss_model = pickle.load(model_file)
    print("XSS Model Loaded")
except Exception as e:
    print(f"Error loading XSS model: {e}")
    xss_model = None

# Function to extract 26 features from input text for XSS detection
def getVec(text):
    features = []
    for line in text:
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()

        # Feature extraction
        feature1 = sum(map(lowerStr.count, ['<link', '<object', '<form', '<embed', '<ilayer', '<layer', '<style', 
                                            '<applet', '<meta', '<img', '<iframe', '<input', '<body', '<video', 
                                            '<button', '<math', '<picture', '<map', '<svg', '<div', '<a', '<details', 
                                            '<frameset', '<table', '<comment', '<base', '<image']))
        feature2 = sum(map(lowerStr.count, ['exec', 'fromcharcode', 'eval', 'alert', 'getelementsbytagname', 'write', 
                                            'unescape', 'escape', 'prompt', 'onload', 'onclick', 'onerror', 
                                            'onpage', 'confirm', 'marquee']))
        feature3 = lowerStr.count('.js')
        feature4 = lowerStr.count('javascript')
        feature5 = len(lowerStr)
        feature6 = sum(map(lowerStr.count, ['<script', '&lt;script', '%3cscript', '%3c%73%63%72%69%70%74']))
        feature7 = sum(map(lowerStr.count, ['&', '<', '>', '"', "'", '/', '%', '*', ';', '+', '=', '%3C']))
        feature8 = lowerStr.count('http')
        feature9 = lowerStr.count('onmouseover')
        feature10 = lowerStr.count('onfocus')
        feature11 = lowerStr.count('<img')
        feature12 = lowerStr.count('src=')
        feature13 = lowerStr.count('alert')
        feature14 = lowerStr.count('script')
        feature15 = lowerStr.count('<svg')
        feature16 = lowerStr.count('onerror')
        feature17 = lowerStr.count('fromcharcode')
        feature18 = lowerStr.count('iframe')
        feature19 = lowerStr.count('formaction')
        feature20 = lowerStr.count('onclick')
        feature21 = lowerStr.count('onload')
        feature22 = lowerStr.count('eval')
        feature23 = lowerStr.count('document.cookie')
        feature24 = lowerStr.count('location.href')
        feature25 = lowerStr.count('prompt')
        feature26 = lowerStr.count('<div')

        featureVec = [feature1, feature2, feature3, feature4, feature5, feature6, feature7, feature8, feature9, 
                      feature10, feature11, feature12, feature13, feature14, feature15, feature16, feature17, 
                      feature18, feature19, feature20, feature21, feature22, feature23, feature24, feature25, feature26]
        
        features.append(featureVec)
    
    return features

def predict_xss(query):
    features = getVec([query])
    
    # Make prediction using the loaded XSS model
    if xss_model:
        prediction_proba = xss_model.predict_proba(features)
        prediction = xss_model.predict(features)
        label = 1 if prediction[0] == 1 else 0
        return label, round(prediction_proba[0][label], 4)
    else:
        return None, None
