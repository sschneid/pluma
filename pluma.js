function maintainValues(name) {
  var group = findFormObject(name);
  if(!group) return;

  var valname = name + '_values';
  var values = findFormObject(valname);
  if(!values) return;
  var grouplist = "";

  for(var i = 0; i < group.length; i++) {
    if(grouplist != "") grouplist += ",";
    grouplist += group.options[i].value;
  }

  values.value = grouplist;
}

function selectItem(srcname, destname, add) {
  var src;
  var dest;
  if(add == null) add = 1;

  if(add) {
    src = findFormObject(srcname);
    dest = findFormObject(destname);
  } else {
    src = findFormObject(destname);
    dest = findFormObject(srcname);
  }

  if(!src || !dest) return;
  var sel = src.selectedIndex;
  if(sel < 0 || sel >= src.length) return;

  var opt = new Option(src.options[sel].text, src.options[sel].value);
  var len = src.length;
  for(var i = sel; i < len-1; i++) {
    src.options[i].value = src.options[i+1].value;
    src.options[i].text = src.options[i+1].text;
  }

  src.selectedIndex = src.selectedIndex - 1;
  if(src.selectedIndex < 0) src.selectedIndex = 0;
  src.options[len-1] = null;

  var ins = dest.length;
  dest.options[ins] = opt;
  dest.selectedIndex = ins;

  maintainValues(destname);
}

function findFormObject(name, doc) {
  if(!doc) doc = document;
  var flen = doc.forms.length;
  for(var i = 0; i < flen; i++) {
    var f = doc.forms[i];
    var ilen = f.elements.length;
    for(var j = 0; j < ilen; j++) {
      var o = f.elements[j];
      if(o.name == name)
        return o;
    }
  }

  alert("Could not find form object '" + name + "'!");
  return null;
}

function delConfirm() {
  return confirm("Are you sure you want to delete this user?");
}

function chgConfirm() {
  return confirm("Changing a group's GID can result in orphaned default user groups.  Are you sure you wish to continue?");
}

function validatePwd() {
  var invalid = " ";
  var minLength = 6;
  var pw1 = document.pwChange.password.value;
  var pw2 = document.pwChange.passwordConfirm.value;

  if (document.pwChange.password.value.length < minLength) {
    alert('Passwords must be at least ' + minLength + ' characters long.');
    return false;
  }

  if (document.pwChange.password.value.indexOf(invalid) > -1) {
    alert("Sorry, spaces are not allowed.");
    return false;
  }

  if (pw1 != pw2) {
    alert("Passwords do not match.");
    return false;
  }

  return true;
}

