# Boilerplate validation code
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# Load dataset (boilerplate) - replace with actual data loading
# Assuming there's a label column named 'label', which has a binary classification for the synthetic/real packets.
df = pd.read_csv('data.csv')  # Placeholder path

X = df.drop(columns=['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1) # Can change split/state as needed

# Data normalization
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# PCA for dimensionality/noise reduction
pca = PCA(n_components=0.95)  # Retain 95% of variance
X_train_pca = pca.fit_transform(X_train_scaled)
X_test_pca = pca.transform(X_test_scaled)

print(f'Original number of features: {X.shape[1]}')
print(f'Number of features after PCA: {X_train_pca.shape[1]}') # Validate that PCA reduced dimensions, if it doesn't we can tweak or remove

# SVM Classifier
svm = SVC(kernel='linear', random_state=1) # Kernel can be changed as needed, same with random_state
svm.fit(X_train_pca, y_train)

# Evaluation
y_pred = svm.predict(X_test_pca)
accuracy = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print(f'Accuracy: {accuracy:.4f}') # If accuracy is ~50% that means our model cannot distinguish between synthetic and real packets
print('Confusion Matrix:\n', cm)
print('Classification Report:\n', classification_report(y_test, y_pred))