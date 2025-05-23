### الوصف الاختياري (Short Description)  
Service Scanner Pro  
أداة متقدمة لفحص خدمات النظام ومراقبة السلوكيات الشاذة باستخدام تقنيات الذكاء الاصطناعي. توفر تحليلاً تفاعليًا ثلاثي الأبعاد، كشف التوقيعات الرقمية المزورة، وواجهة مستخدم جذابة مع إمكانية تصدير النتائج بتنسيقات متعددة.

---

 
# Service-process Scanner Pro 🛡️  
**أداة متقدمة لاكتشاف الخدمات المشبوهة والشاذة في نظامك باستخدام التعلم الآلي.**  









![‏‏لقطة الشاشة (264)](https://github.com/user-attachments/assets/540d2486-a34e-4494-8877-554103bd2607)





![‏‏لقطة الشاشة (220)](https://github.com/user-attachments/assets/fd5bdcbb-ec9f-4703-aa02-5ed765c5ab77)


![‏‏لقطة الشاشة (225)](https://github.com/user-attachments/assets/dacbc33a-d19d-4c88-ab90-090bf0e0a7c8)





---

## 📌 الميزات الرئيسية  
- **كشف الحالات الشاذة**: استخدام خوارزمية **Isolation Forest** للتعلم غير المراقب.  
- **التحقق من التوقيعات الرقمية**: فحص مصداقية الملفات التنفيذية باستخدام أداة `signtool`.  
- **واجهة تفاعلية ثلاثية الأبعاد**: عرض البيانات عبر مخططات رادار ورسوم بيانية ديناميكية.  
- **تحليل الشبكات**: تتبع اتصالات TCP/UDP والعمليات المستترة.  
- **التصدير المرن**: دعم تصدير النتائج إلى Excel، PDF، HTML.  
- **إدارة العمليات**: إيقاف/تعليق/تحقيق في العمليات المشبوهة مباشرةً من الواجهة.  

---

## ⚙️ المتطلبات  
- Python 3.8+  
- نظام تشغيل **Windows** (مدعوم بالكامل) أو **Linux/macOS** (محدود الوظائف).  
- المكتبات المطلوبة:  
  
bash
  pip install psutil tkinter pandas scikit-learn matplotlib openpyxl joblib mplcursors
 

---

## 🚀 التثبيت والبدء  
1. انسخ المستودع:  
   
bash
   git clone https://github.com/your-username/Service-Scanner-Pro.git  
   cd Service-Scanner-Pro  
  
2. ثبت المكتبات:  
   
bash
   pip install -r requirements.txt  
  
3. شغّل الأداة:  
   
bash
   python service_scanner.py  
  

---

## 🖥️ شرح الواجهة  
### تبويبات رئيسية:  
1. **Welcome Screen**: عرض مؤثرات بصرية مع ملخص ميزات الأداة.  
2. **Scan Process**: فحص العمليات النشطة وتحليل الحمولة.  
3. **Keywords Scan**: البحث عن عمليات تحتوي على كلمات مفتاحية مشبوهة.  
4. **Suspicious Services**: قائمة بالخدمات المخفية أو ذات التوقيعات المزورة.  

### الأزرار الأساسية:  
- **Collect Baseline**: جمع بيانات أساسية لتدريب النموذج.  
- **Train Model**: تدريب نموذج Isolation Forest على البيانات.  
- **Export**: تصدير النتائج بتنسيقات مختلفة.  

---

## 📊 مثال على الاستخدام  
1. انقر على **Collect Baseline** لجمع بيانات التدريب.  
2. اضغط على **Train Model** لبناء النموذج.  
3. استخدم **Scan Process** لفحص العمليات الحالية.  
4. اعتمد على علامات التبويب لتحليل النتائج واتخاذ الإجراءات.  

---

## 🤝 المساهمة في المشروع  
- المرحب بالتقارير عن الأخطاء أو طلبات الميزات عبر [Issues](https://github.com/your-username/Service-Scanner-Pro/issues).  
- لإنشاء فرع وتقديم تعديلات:  
  
bash
  git checkout -b feature/your-feature  
  git push origin feature/your-feature  
  `

---

## 📜 الترخيص  
هذا المشروع مرخص تحت [MIT License](LICENSE).  

---

🙏طور بواسطة
 [Ali Ali AL-sha'abi]
Bachelor of Cyber ​​Security and Networks, Amran University
 ✨️🥇   يسعدني أن 
أشارك معكم أحد مشاريعي البرمجية، والذي قمت بتطويره باستخدام لغة Python بهدف تعزيز قدراتي العملية في مجال تقنية المعلومات وتحليل البيانات 

  للأطلاع أكثر لمزيد المشاريع تابع صفحتي على    https://github.com/morgansir
  or https://www.facebook.com/profile.php?id=100055181233147
  
