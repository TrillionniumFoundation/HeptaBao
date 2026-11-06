#!/usr/bin/env python3
"""Compile the frozen production classes with host stubs; no Android/ADB claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PINNED = {
    'VaultApplication.java': 'b6714fc013e82af862f85a0224ea23acdeea92ddd1747a472636d0951f677da1',
    'AuthActivity.java': '8410b9b9c183c63d9b776086d0ce1b931eddc5aebff8908bff727a23a94ffc85',
}

STUBS = {
'android/content/Context.java': '''package android.content;
public class Context { public String getPackageName() { return "org.heptabao.preview"; } }
''',
'android/content/ComponentName.java': '''package android.content;
public final class ComponentName {
 private final String p,c; public ComponentName(String p,String c){this.p=p;this.c=c;}
 public String getPackageName(){return p;} public boolean equals(Object o){return o instanceof ComponentName && p.equals(((ComponentName)o).p)&&c.equals(((ComponentName)o).c);}
 public int hashCode(){return p.hashCode()*31+c.hashCode();}
}
''',
'android/content/Intent.java': '''package android.content;
public class Intent { private android.net.Uri data; private final java.util.Map<String,Object> extras=new java.util.HashMap<>();
 public Intent setData(android.net.Uri value){data=value;return this;} public android.net.Uri getData(){return data;}
 public Intent putExtra(String name,Object value){extras.put(name,value);return this;}
 public <T> T getParcelableExtra(String name,Class<T> type){return type.cast(extras.get(name));}
}
''',
'android/net/Uri.java': '''package android.net;
public final class Uri { private final java.net.URI value; private Uri(String s){value=java.net.URI.create(s);}
 public static Uri parse(String s){return new Uri(s);} public String getScheme(){return value.getScheme();}
 public String getHost(){return value.getHost();} public String getLastPathSegment(){String p=value.getPath();return p.substring(p.lastIndexOf('/')+1);}
}
''',
'android/os/Parcelable.java': 'package android.os; public interface Parcelable {}',
'android/os/Bundle.java': 'package android.os; public class Bundle {}',
'android/os/SystemClock.java': 'package android.os; public final class SystemClock { public static volatile long now=1000; public static long elapsedRealtime(){return now;} }',
'android/os/Looper.java': 'package android.os; public final class Looper { private static final Looper MAIN=new Looper(); public static Looper getMainLooper(){return MAIN;} }',
'android/os/Handler.java': '''package android.os;
public final class Handler { private final java.util.concurrent.ConcurrentLinkedQueue<Runnable> q=new java.util.concurrent.ConcurrentLinkedQueue<>();
 public Handler(Looper l){} public boolean post(Runnable r){q.add(r);return true;}
 public boolean postDelayed(Runnable r,long ms){return true;} public void removeCallbacks(Runnable r){q.remove(r);}
 public void drain(){int n=0;Runnable r;while((r=q.poll())!=null){if(++n>100)throw new AssertionError("handler_loop");r.run();}}
}
''',
'android/app/Application.java': '''package android.app;
public class Application extends android.content.Context {
 public static final int TRIM_MEMORY_RUNNING_MODERATE=5,TRIM_MEMORY_RUNNING_LOW=10,TRIM_MEMORY_RUNNING_CRITICAL=15,TRIM_MEMORY_UI_HIDDEN=20,TRIM_MEMORY_BACKGROUND=40,TRIM_MEMORY_MODERATE=60,TRIM_MEMORY_COMPLETE=80;
 public void onCreate(){} public void onTrimMemory(int level){}
}
''',
'android/app/PendingIntent.java': 'package android.app; public final class PendingIntent { public volatile int cancelled=0; public synchronized void cancel(){cancelled++;} }',
'android/app/Activity.java': '''package android.app;
public class Activity extends android.content.Context {
 public static final int RESULT_OK=-1,RESULT_CANCELED=0; public Application testApp; public android.content.Intent testIntent; public android.content.ComponentName testCaller; public int resultCode;
 private boolean finishing; private final android.view.Window window=new android.view.Window();
 public Application getApplication(){return testApp;} public android.content.Intent getIntent(){return testIntent;}
 public android.content.ComponentName getCallingActivity(){return testCaller;} public android.view.Window getWindow(){return window;}
 public void setResult(int code,android.content.Intent result){resultCode=code;} public void finish(){finishing=true;} public boolean isFinishing(){return finishing;}
 public void setContentView(android.view.View view){} public void onCreate(android.os.Bundle b){}
 protected void onResume(){} protected void onPause(){} protected void onSaveInstanceState(android.os.Bundle b){}
}
''',
'android/app/assist/AssistStructure.java': 'package android.app.assist; public class AssistStructure implements android.os.Parcelable {}',
'android/util/Log.java': '''package android.util; public final class Log {
 public static final java.util.List<String> events=java.util.Collections.synchronizedList(new java.util.ArrayList<>());
 public static int i(String tag,String value){events.add(value);return 0;}
}
''',
'android/text/Editable.java': '''package android.text;
public final class Editable implements CharSequence { private final String value; public Editable(String s){value=s;}
 public int length(){return value.length();} public char charAt(int i){return value.charAt(i);}
 public CharSequence subSequence(int a,int b){return value.subSequence(a,b);} public String toString(){return value;}
 public void getChars(int a,int b,char[] dest,int offset){value.getChars(a,b,dest,offset);}
}
''',
'android/text/InputType.java': 'package android.text; public final class InputType {public static final int TYPE_CLASS_TEXT=1,TYPE_TEXT_VARIATION_PASSWORD=128;}',
'android/view/inputmethod/EditorInfo.java': 'package android.view.inputmethod; public final class EditorInfo {public static final int IME_FLAG_NO_PERSONALIZED_LEARNING=1;}',
'android/view/View.java': '''package android.view; public class View {
 public static final int IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS=8; private boolean enabled=true;
 public interface OnClickListener{void onClick(View v);} private OnClickListener listener;
 public void setEnabled(boolean b){enabled=b;} public boolean isEnabled(){return enabled;} public void setImportantForAutofill(int x){}
 public void setOnClickListener(OnClickListener l){listener=l;} public void performClick(){if(enabled&&listener!=null)listener.onClick(this);}
}
''',
'android/view/Window.java': 'package android.view; public final class Window {public void addFlags(int value){}}',
'android/view/WindowManager.java': 'package android.view; public final class WindowManager {public static final class LayoutParams {public static final int FLAG_SECURE=8192;}}',
'android/widget/TextView.java': '''package android.widget; public class TextView extends android.view.View {
 protected CharSequence text=""; public TextView(android.content.Context c){} public void setText(CharSequence s){text=s;}
 public CharSequence getText(){return text;} public void setTextSize(int s){} public void setContentDescription(String s){}
}
''',
'android/widget/EditText.java': '''package android.widget; public final class EditText extends TextView {
 public EditText(android.content.Context c){super(c);} public android.text.Editable getText(){return new android.text.Editable(text.toString());}
 public void setHint(String s){} public void setInputType(int x){} public void setImeOptions(int x){}
 public void setSaveEnabled(boolean b){} public void setLongClickable(boolean b){} public void setAutofillHints(String[] s){}
}
''',
'android/widget/Button.java': 'package android.widget; public final class Button extends TextView {public Button(android.content.Context c){super(c);}}',
'android/widget/LinearLayout.java': '''package android.widget; public final class LinearLayout extends android.view.View {
 public static final int VERTICAL=1; public LinearLayout(android.content.Context c){} public void setOrientation(int v){}
 public void setPadding(int a,int b,int c,int d){} public void addView(android.view.View v){}
}
''',
'android/widget/RemoteViews.java': 'package android.widget; public final class RemoteViews {public RemoteViews(String p,int r){} public void setTextViewText(int i,CharSequence s){}}',
'android/view/autofill/AutofillManager.java': '''package android.view.autofill; public final class AutofillManager {
 public static final String EXTRA_AUTHENTICATION_RESULT="result",EXTRA_AUTHENTICATION_RESULT_EPHEMERAL_DATASET="ephemeral",EXTRA_ASSIST_STRUCTURE="structure";
}
''',
'android/view/autofill/AutofillValue.java': 'package android.view.autofill; public final class AutofillValue {public static AutofillValue forText(CharSequence s){return new AutofillValue();}}',
'android/service/autofill/Dataset.java': '''package android.service.autofill; public final class Dataset implements android.os.Parcelable {
 public static final class Builder { public Builder(android.widget.RemoteViews r){} public Builder setValue(Object id,android.view.autofill.AutofillValue v){return this;} public Dataset build(){return new Dataset();} }
}
''',
'org/heptabao/preview/R.java': 'package org.heptabao.preview; final class R {static final class layout {static final int presentation=1;} static final class id {static final int presentation_text=2;}}',
'org/heptabao/preview/BuildConfig.java': 'package org.heptabao.preview; final class BuildConfig {static final String ENTRY_ID="synthetic",ENTRY_ORIGIN="https://synthetic.invalid";}',
'org/heptabao/preview/TargetPolicy.java': '''package org.heptabao.preview;
final class TargetPolicy {
 static final class Rejected extends Exception {final String code;Rejected(String s){code=s;}}
 static final class Target {final android.content.ComponentName component=new android.content.ComponentName("org.heptabao.fixture","org.heptabao.fixture.MainActivity");
  final Object username=new Object(),password=new Object();boolean same(Target t){return this==t;}}
 static Target target; static Target inspect(android.content.Context c,android.app.assist.AssistStructure s)throws Rejected{if(s==null)throw new Rejected("wrong_target");return target;}
 static void certificate(android.content.Context c,String p)throws Rejected{}
}
''',
'org/heptabao/preview/VaultFiles.java': 'package org.heptabao.preview; final class VaultFiles {static byte[] read(android.content.Context c)throws java.io.IOException{return new byte[]{1};}}',
'org/heptabao/preview/VaultCrypto.java': '''package org.heptabao.preview;
final class VaultCrypto {
 static final class Failure extends Exception{final String code;Failure(String s){code=s;}}
 static final class Login implements AutoCloseable {final char[] username="CANARY_USERNAME".toCharArray(),password="CANARY_CREDENTIAL".toCharArray();volatile boolean closed;
  public void close(){java.util.Arrays.fill(username,'\\0');java.util.Arrays.fill(password,'\\0');closed=true;}}
 static volatile java.util.concurrent.CountDownLatch entered,release; static volatile Login last; static volatile byte[] lastPassword;
 static void block(){entered=new java.util.concurrent.CountDownLatch(1);release=new java.util.concurrent.CountDownLatch(1);last=null;lastPassword=null;}
 static byte[] passwordBytes(char[] chars)throws Failure{return new String(chars).getBytes(java.nio.charset.StandardCharsets.UTF_8);}
 static Login unlock(byte[] vault,byte[] password,String id,String origin)throws Failure{
  lastPassword=password; java.util.concurrent.CountDownLatch e=entered,r=release;
  if(e!=null){e.countDown();try{if(!r.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new Failure("host_timeout");}catch(InterruptedException x){Thread.currentThread().interrupt();throw new Failure("host_interrupted");}}
  last=new Login();return last;
 }
}
''',
}

HARNESS = r'''package org.heptabao.preview;
import android.app.Application;
import android.app.PendingIntent;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class LifecycleChecks {
 private static final List<String> passed=new ArrayList<>();
 interface Check{void run()throws Exception;}
 static void ok(boolean condition,String code){if(!condition)throw new AssertionError(code);}
 static void test(String name,Check body)throws Exception{body.run();passed.add(name);}
 static VaultApplication app(){SystemClock.now=1000;VaultApplication a=new VaultApplication();a.onCreate();return a;}
 static TargetPolicy.Target target(){TargetPolicy.target=new TargetPolicy.Target();return TargetPolicy.target;}
 static VaultApplication.Pending pending(VaultApplication a){VaultApplication.Pending p=a.begin(target());a.attachLaunch(p.token,new PendingIntent());return p;}
 static void flush(VaultApplication a)throws Exception{a.cancellationWorker.submit(()->{}).get(3,TimeUnit.SECONDS);}
 static void stop(VaultApplication a)throws Exception{
  VaultCrypto.release=null;VaultCrypto.entered=null;
  a.lockAll("host_stop");flush(a);a.timers.shutdownNow();a.cryptoWorker.shutdownNow();a.importWorker.shutdownNow();a.cancellationWorker.shutdownNow();
 }
 static boolean zero(char[] a){for(char c:a)if(c!=0)return false;return true;}
 static boolean zero(byte[] a){for(byte c:a)if(c!=0)return false;return true;}
 static VaultCrypto.Login login(VaultApplication a,VaultApplication.Pending p){VaultCrypto.Login v=new VaultCrypto.Login();ok(a.install(p.token,a.ticket(p.token),v),"install");return v;}
 static AuthActivity activity(VaultApplication a,VaultApplication.Pending p)throws Exception{
  AuthActivity ui=new AuthActivity();ui.testApp=a;ui.testCaller=p.target.component;
  ui.testIntent=new android.content.Intent().setData(android.net.Uri.parse("heptabao-auth://local/"+p.token))
   .putExtra(android.view.autofill.AutofillManager.EXTRA_ASSIST_STRUCTURE,new android.app.assist.AssistStructure());
  ui.onCreate(null);ui.onResume();a.handler.drain();ok(!ui.isFinishing(),"initial_context");return ui;
 }
 static Object field(AuthActivity ui,String name)throws Exception{java.lang.reflect.Field f=AuthActivity.class.getDeclaredField(name);f.setAccessible(true);return f.get(ui);}
 static android.widget.Button button(AuthActivity ui)throws Exception{return (android.widget.Button)field(ui,"unlock");}
 static String status(AuthActivity ui)throws Exception{return ((android.widget.TextView)field(ui,"status")).getText().toString();}
 static void beginKdf(AuthActivity ui)throws Exception{
  VaultCrypto.block();((android.widget.EditText)field(ui,"master")).setText("CANARY_MASTER_password");button(ui).performClick();
  ok(!button(ui).isEnabled(),"unlock_disabled_in_flight");ok(VaultCrypto.entered.await(3,TimeUnit.SECONDS),"kdf_entered");
 }
 static void finishKdf(VaultApplication a)throws Exception{
  VaultCrypto.release.countDown();a.cryptoWorker.submit(()->{}).get(3,TimeUnit.SECONDS);a.handler.drain();
  ok(zero(VaultCrypto.lastPassword),"input_password_cleared");
 }
 static void assertStale(VaultApplication a,VaultApplication.Pending p)throws Exception{
  ok(VaultCrypto.last!=null&&VaultCrypto.last.closed&&zero(VaultCrypto.last.password)&&zero(VaultCrypto.last.username),"stale_result_cleared");
  ok(!a.isUnlocked(p.token),"stale_result_not_installed");
 }
 public static void main(String[] argv)throws Exception {
  test("opaque_pending_and_deadline_preserved_epoch_revoked",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);PendingIntent pi=p.launch;Object timer=p.timeout;long deadline=p.deadline,ticket=a.ticket(p.token);SystemClock.now+=40000;
   a.onTrimMemory(Application.TRIM_MEMORY_BACKGROUND);flush(a);
   ok(a.request(p.token)==p&&p.launch==pi&&p.timeout==timer&&p.deadline==deadline&&!p.timeout.isCancelled()&&pi.cancelled==0,"same_bounded_pending");
   ok(a.ticket(p.token)==ticket+1,"epoch_advanced_when_login_null");VaultCrypto.Login v=new VaultCrypto.Login();ok(!a.install(p.token,ticket,v)&&v.closed,"old_ticket_rejected");
  }finally{stop(a);}});
  test("ui_hidden_revokes_login_without_new_challenge",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);VaultCrypto.Login v=login(a,p);long deadline=p.deadline,ticket=a.ticket(p.token);a.onTrimMemory(Application.TRIM_MEMORY_UI_HIDDEN);
   ok(v.closed&&zero(v.password)&&zero(v.username)&&!a.isUnlocked(p.token),"login_cleared");ok(a.request(p.token)==p&&p.deadline==deadline&&a.ticket(p.token)==ticket+1,"pending_not_renewed");
  }finally{stop(a);}});
  test("active_handoff_revoked_and_pending_not_resurrected",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);VaultCrypto.Login v=login(a,p);VaultApplication.Handoff h=a.consume(p.token);ok(h!=null&&a.handoffValid(h),"valid_handoff");
   a.onTrimMemory(Application.TRIM_MEMORY_RUNNING_LOW);flush(a);ok(v.closed&&!a.handoffValid(h)&&a.request(p.token)==null&&p.launch.cancelled==1,"handoff_revoked");
  }finally{stop(a);}});
  test("cancel_after_trim_clears_pending_and_launch",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);a.onTrimMemory(Application.TRIM_MEMORY_BACKGROUND);a.cancel(p.token);flush(a);
   ok(a.request(p.token)==null&&p.launch.cancelled==1&&p.timeout.isCancelled(),"cancel_still_full");
  }finally{stop(a);}});
  test("request_expires_at_original_deadline",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);long deadline=p.deadline;SystemClock.now=deadline-1;a.onTrimMemory(Application.TRIM_MEMORY_COMPLETE);ok(a.request(p.token)==p,"live_before_deadline");
   SystemClock.now=deadline;ok(a.request(p.token)==null,"exact_original_expiry");flush(a);ok(p.launch.cancelled==1,"expired_launch_cancelled");
  }finally{stop(a);}});
  test("import_after_trim_remains_full_lock",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);a.onTrimMemory(Application.TRIM_MEMORY_BACKGROUND);ok(a.startImport(),"import_started");flush(a);
   ok(a.isImporting()&&a.request(p.token)==null&&p.launch.cancelled==1,"import_invalidates_challenge");a.endImport("imported_locked");ok(!a.isImporting()&&a.request(p.token)==null,"import_cannot_restore");
  }finally{stop(a);}});
  test("replacement_keeps_only_new_bounded_pending",()->{VaultApplication a=app();try{
   VaultApplication.Pending old=pending(a);SystemClock.now+=50;VaultApplication.Pending current=pending(a);a.onTrimMemory(Application.TRIM_MEMORY_BACKGROUND);flush(a);
   ok(a.request(old.token)==null&&old.launch.cancelled==1&&a.request(current.token)==current&&current.launch.cancelled==0,"one_pending_only");
  }finally{stop(a);}});
  test("trim_during_actual_unlock_discards_result_and_allows_fresh_retry",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);a.onTrimMemory(Application.TRIM_MEMORY_BACKGROUND);finishKdf(a);assertStale(a,p);
   ok(button(ui).isEnabled()&&status(ui).equals("Locked or expired"),"foreground_retry_reenabled");
   beginKdf(ui);finishKdf(a);ok(a.isUnlocked(p.token)&&!VaultCrypto.last.closed&&status(ui).equals("Unlocked; confirm within 20 seconds"),"fresh_ticket_success_control");
  }finally{stop(a);}});
  test("background_during_actual_unlock_never_reenables_or_installs",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);ui.onPause();finishKdf(a);assertStale(a,p);
   ok(!button(ui).isEnabled()&&a.request(p.token)==null,"background_stays_cancelled");
  }finally{stop(a);}});
  test("finishing_during_actual_unlock_never_reenables_or_installs",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);ui.finish();finishKdf(a);assertStale(a,p);
   ok(!button(ui).isEnabled(),"finishing_stays_disabled");
  }finally{stop(a);}});
  test("cancelled_foreground_request_cannot_be_restored_by_callback",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);a.cancel(p.token);finishKdf(a);assertStale(a,p);
   ok(!button(ui).isEnabled()&&a.request(p.token)==null,"cancel_not_recreated");
  }finally{stop(a);}});
  test("replacement_request_does_not_reenable_old_activity",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);VaultApplication.Pending next=pending(a);finishKdf(a);assertStale(a,p);
   ok(!button(ui).isEnabled()&&a.request(next.token)==next&&!a.isUnlocked(next.token),"replacement_separation");
  }finally{stop(a);}});
  test("expired_foreground_request_cannot_be_restored_by_callback",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);SystemClock.now=p.deadline;finishKdf(a);assertStale(a,p);
   ok(!button(ui).isEnabled()&&a.request(p.token)==null,"expired_not_recreated");
  }finally{stop(a);}});
  test("explicit_lock_during_unlock_discards_old_result",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);a.lockLogin(p.token);finishKdf(a);assertStale(a,p);
   ok(button(ui).isEnabled()&&status(ui).equals("Locked or expired"),"explicit_lock_retry_safe");
  }finally{stop(a);}});
  test("wrong_result_recipient_after_kdf_fails_closed",()->{VaultApplication a=app();try{
   VaultApplication.Pending p=pending(a);AuthActivity ui=activity(a,p);beginKdf(ui);ui.testCaller=new android.content.ComponentName("wrong.fixture","wrong.fixture.Main");finishKdf(a);assertStale(a,p);
   ok(a.request(p.token)==null&&status(ui).equals("Authorization rejected"),"wrong_recipient_not_installed");
  }finally{stop(a);}});
  test("closed_trim_diagnostics_never_include_identity_or_credentials",()->{VaultApplication a=app();try{
   android.util.Log.events.clear();VaultApplication.Pending p=pending(a);int[] levels={5,10,15,20,40,60,80,-519933};
   String[] labels={"running_moderate","running_low","running_critical","ui_hidden","background","moderate","complete","other"};
   for(int i=0;i<levels.length;i++){VaultCrypto.Login v=login(a,p);a.onTrimMemory(levels[i]);String s=android.util.Log.events.get(i);
    ok(s.equals("trim_"+labels[i]+"_before_p1l1h0_after_p1l0h0_epoch_advanced"),"closed_log_schema");
    ok(v.closed&&!s.contains(p.token)&&!s.contains("CANARY")&&!s.contains("519933")&&!s.contains("org.heptabao"),"no_secret_or_identity_log");}
  }finally{stop(a);}});
  if(passed.size()!=16)throw new AssertionError("case_count");
  System.out.print("{\"scope\":\"host_lifecycle_with_android_and_crypto_stubs_only\",\"passed\":16,\"expected\":16,\"failed\":0,\"cases\":[");
  for(int i=0;i<passed.size();i++){if(i>0)System.out.print(",");System.out.print("\""+passed.get(i)+"\"");}
  System.out.println("],\"adb_calls\":0,\"android_runtime_tested\":false,\"crypto_tested\":false,\"external_review\":false,\"production_qualified\":false}");
 }
}
'''

def durable(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, default=Path('/workspace/scratch/848006513f75/HeptaBao'))
    p.add_argument('--work', type=Path, required=True)
    args = p.parse_args()
    if not args.work.is_absolute():
        p.error('--work must be a new absolute directory')
    originals = {}
    for name, expected in PINNED.items():
        data = (args.repo/'clients/android/provider/java/org/heptabao/preview'/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit('frozen product source changed: ' + name)
        originals[name] = data
    args.work.mkdir(mode=0o700, parents=False, exist_ok=False)
    src, classes = args.work/'src', args.work/'classes'
    src.mkdir(mode=0o700); classes.mkdir(mode=0o700)
    sources = dict(STUBS)
    sources['org/heptabao/preview/LifecycleChecks.java'] = HARNESS
    for name, data in originals.items():
        sources['org/heptabao/preview/' + name] = data
    paths = []
    for relative, data in sources.items():
        path = src/relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        durable(path, data.encode() if isinstance(data, str) else data)
        paths.append(str(path))
    java = Path(shutil.which('java') or '/usr/bin/java').resolve(strict=True)
    version = subprocess.run([str(java), '-version'], capture_output=True, timeout=10, check=True)
    compile_argv = [str(java), '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-d', str(classes)] + sorted(paths)
    compiled = subprocess.run(compile_argv, capture_output=True, timeout=30)
    durable(args.work/'compile.stdout.original.txt', compiled.stdout)
    durable(args.work/'compile.stderr.original.txt', compiled.stderr)
    if compiled.returncode:
        raise SystemExit('host compiler failed; private log retained')
    run_argv = [str(java), '-cp', str(classes), 'org.heptabao.preview.LifecycleChecks']
    ran = subprocess.run(run_argv, capture_output=True, timeout=30)
    durable(args.work/'run.stdout.original.json', ran.stdout)
    durable(args.work/'run.stderr.original.txt', ran.stderr)
    if ran.returncode:
        raise SystemExit('host lifecycle checks failed; private log retained')
    result = json.loads(ran.stdout)
    if result['expected'] != 16 or result['passed'] != 16 or result['failed'] != 0:
        raise SystemExit('invalid host case result')
    for name, expected in PINNED.items():
        if hashlib.sha256((args.repo/'clients/android/provider/java/org/heptabao/preview'/name).read_bytes()).hexdigest() != expected:
            raise SystemExit('product source changed during host run')
    receipt = {
        'schema': 1, 'scope': 'author_host_lifecycle_tests_only',
        'product_source_sha256': PINNED,
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'java_binary_sha256': hashlib.sha256(java.read_bytes()).hexdigest(),
        'java_version': (version.stdout + version.stderr).decode().strip(),
        'compiler_mode': 'installed JDK default target; minimal Android/crypto/policy stubs; not SDK compilation',
        'compile_exit_code': compiled.returncode, 'run_exit_code': ran.returncode,
        'compile_argv': compile_argv, 'run_argv': run_argv,
        'result_stdout_sha256': hashlib.sha256(ran.stdout).hexdigest(),
        'result': result,
        'limits': ['No Android OS lifecycle dispatch evidence', 'No certificate or crypto validation in stubs', 'No actual Autofill framework, UI, PendingIntent delivery or device memory-pressure test', 'No proof of r7 root cause'],
    }
    data = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
    durable(args.work/'host-check.public.json', data)
    fd = os.open(args.work, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    print(json.dumps({'scope': receipt['scope'], 'passed': result['passed'], 'expected': result['expected'], 'receipt_sha256': hashlib.sha256(data).hexdigest(), 'receipt': str(args.work/'host-check.public.json')}))

if __name__ == '__main__':
    main()
