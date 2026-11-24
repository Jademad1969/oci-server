# خطة التراجع السريع والطوارئ (Rollback Plan) — DIC ERP

هذا الملف يشرح خطوات التراجع الآمن في حالة ظهور أي مشكلة بعد النشر على **بيئة التشغيل (Production)**.

---

## الحالة الأولى: مشكلة في الكود فقط (الأكثر شيوعاً — خلال أقل من 30 ثانية)
إذا كانت التعديلات الجديدة في قاعدة البيانات إضافية فقط (جداول أو أعمدة جديدة)، يكفي التراجع عن الكود فقط:

### 1. الاتصال بسيرفر التشغيل عبر SSH:
```powershell
ssh -i .\ssh-key-2026-11-14.key ubuntu@<SERVER_IP>
```

### 2. عرض آخر الـ Commits ومعرفة الكوميت السابق المستقر:
```bash
cd /home/ubuntu/dic_erp_prod
git log -n 5 --oneline
```

### 3. الرجوع للكوميت السابق المستقر وإعادة تشغيل التطبيق:
```bash
git reset --hard <PREVIOUS_COMMIT_HASH>
docker restart dic_web_prod
```

### 4. التحقق من عودة النظام للعمل:
```bash
curl -s http://127.0.0.1:8000/health
```

> **ملاحظة:** بعد استقرار التشغيل، يُفضّل عمل `git revert` على فرع `main` و `test` على جهازك المحلي لإبقاء سجل Git متزامناً مع السيرفر.

---

## الحالة الثانية: التراجع عن قاعدة البيانات أيضاً (Database Restore)
سكربت `scripts/deploy_to_prod.ps1` يأخذ تلقائياً نسخة احتياطية كاملة قبل كل عملية نشر داخل المجلد:
`/home/ubuntu/dic_erp_prod/backups/prod_before_deploy_YYYYMMDD_HHMMSS.sql`

### خطوات الاسترجاع الكامل لقاعدة البيانات:
```bash
cd /home/ubuntu/dic_erp_prod

# 1. عرض أحدث ملفات النسخ الاحتياطي
ls -lh backups/

# 2. إيقاف حاوية التطبيق مؤقتاً لمنع الكتابة أثناء الاسترجاع
docker stop dic_web_prod

# 3. استرجاع قاعدة البيانات من النسخة الاحتياطية المطلوبة
docker exec -i dic_db_prod psql -U dic_admin -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'dic_donor_prod' AND pid <> pg_backend_pid();"
docker exec -i dic_db_prod dropdb -U dic_admin --if-exists dic_donor_prod
docker exec -i dic_db_prod createdb -U dic_admin dic_donor_prod
docker exec -i dic_db_prod psql -U dic_admin -d dic_donor_prod < backups/prod_before_deploy_YYYYMMDD_HHMMSS.sql

# 4. إعادة تشغيل التطبيق والتحقق
docker start dic_web_prod
curl -s http://127.0.0.1:8000/health
```

---

## ملخص طبقات الأمان التلقائية أثناء النشر
1. **نسخة احتياطية إلزامية (`pg_dump`)** قبل سحب الكود أو تنفيذ أي SQL.
2. **حماية Transaction (`BEGIN; ... COMMIT;`)** مع `ON_ERROR_STOP=1` لمنع أي تعديل جزئي في قاعدة البيانات.
3. **فحص `/health` تلقائي** بعد إعادة تشغيل الحاوية للتأكد من نجاح الإقلاع.
