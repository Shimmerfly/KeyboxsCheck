# The keybox engine parses X.509 chains and DER private keys through the JDK
# security providers. Those lookups are reflective, so R8 cannot see them and
# would otherwise strip or rewrite the classes the providers resolve at runtime.
-keep class dev.hcy917.keyboxchecker.keybox.** { *; }

# org.json is part of the platform, but the classifier and report writer call
# it directly; keep it so shrinking cannot remove the referenced members.
-keep class org.json.** { *; }

# XML parsing goes through javax.xml and the SAX/DOM implementations shipped
# with the platform, plus provider classes that are not on the compile classpath.
-dontwarn javax.xml.**
-dontwarn java.security.**
-dontwarn sun.security.**
-dontwarn org.xml.sax.**

# OkHttp and Okio reference optional platform integrations that are absent here.
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Attributes the runtime needs when resolving certificates and Compose state.
-keepattributes Signature
-keepattributes InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeInvisibleAnnotations, AnnotationDefault
