import { validateEmail } from '../tools/_regex_utils.mjs';
import './modules/crash_report.mjs';

import {Modes} from './modules/modes.mjs';
import * as Settings from './modules/settings.mjs';
import * as Icon from './modules/_icon.mjs';


// Set the translated texts for the options page
(function() {
  const getMsg = chrome.i18n.getMessage;

  $('div#waitlist strong').html(getMsg('waitlist_title'));
  $('p#waitlist_message').html(getMsg('waitlist_message'));
  $('button#waitlist_button').html(getMsg('waitlist_button'));
  $('#waitlist_txt_email').prop('placeholder', getMsg('waitlist_txt_email_placeholder'));

  chrome.storage.sync.get(['user'], function(items) {
    if(items.hasOwnProperty('user')) {
      items = JSON.parse(items.user)
      $('#waitlist').hide();
      $('#login').hide();
      $('div#loggedin strong').html(getMsg('loggedin_welcome') + ' ' + items.username);
      $('#loggedin_message').html(getMsg('loggedin_plan') + ' <b>' + (items.state == 1) ? 'Free user' : (items.state == 2) ? 'Pro user' : 'Error!' + '</b>');
      $('#loggedin').show();
    }
  });

  $('#waitlist_button').on('click', async function() {
    if($('#waitlist_txt_email').val() != '') {
      if(validateEmail($('#waitlist_txt_email').val())) {
        const rawResponse = await fetch('https://unblock-backend.54nft.io/waitlist', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({email: $('#waitlist_txt_email').val()})
        });
        const content = await rawResponse.json();
        if(!content.success) {
          $('#waitlist_txt_email_message').removeClass().addClass('alert alert-danger').html(content.error).show();
        }
        if(content.success) {
          $('#waitlist_txt_email').val('');
          $('#waitlist_txt_email_message').removeClass().addClass('alert alert-success').html(getMsg('waitlist_sent')).show();
        }
      } else {
        $('#waitlist_txt_email_message').removeClass().addClass('alert alert-danger').html(getMsg('waitlist_email_not_valid')).show();
      }
    } else {
      $('#waitlist_txt_email_message').removeClass().addClass('alert alert-danger').html(getMsg('waitlist_email_blank')).show();
    }
  });

  $('div#login strong').html(getMsg('login_title'));
  $('p#login_message').html(getMsg('login_message'));
  $('#login_txt_register').html(getMsg('login_txt_register'));
  $('button#login_button').html(getMsg('login_button'));
  $('#login_txt_email').prop('placeholder', getMsg('login_txt_email_placeholder'));
  $('#login_txt_password').prop('placeholder', getMsg('login_txt_password_placeholder'));

  $('#login_button').on('click', async function() {
    if($('#login_txt_email').val() != '') {
      if($('#login_txt_password').val() != '') {
        const rawResponse = await fetch('https://unblock-backend.54nft.io/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({user: $('#login_txt_email').val(), password: $('#login_txt_password').val()})
        });
        const content = await rawResponse.json();
        if(!content.success) {
          $('#login_txt_email_message').removeClass().addClass('alert alert-danger').html(content.error).show();
        }
        if(content.success) {
          chrome.storage.sync.set({'user': JSON.stringify(content.result[0])}, function() {
            $('#waitlist').hide();
            $('#login').hide();
            $('#login_txt_email').val('');
            $('#login_txt_password').val('');
            $('div#loggedin strong').html(getMsg('loggedin_welcome') + ' ' + content.result[0].username);
            $('#loggedin_message').html(getMsg('loggedin_plan') + ' <b>' + (content.result[0].state == 1) ? 'Free user' : (content.result[0].state == 2) ? 'Pro user' : 'Error!' + '</b>');
            $('#login_txt_email_message').hide();
            $('#loggedin').show();
          });
        }
      } else {
        $('#login_txt_email_message').removeClass().addClass('alert alert-danger').html(getMsg('login_password_blank')).show();
      }
    } else {
      $('#login_txt_email_message').removeClass().addClass('alert alert-danger').html(getMsg('login_email_blank')).show();
    }
  });

  $('#loggedin_button').on('click', async function() {
    chrome.storage.sync.remove(['user']);
    $('div#loggedin strong').html('');
    $('#loggedin_message').html('');
    $('#loggedin').hide();
    $('#waitlist').show();
    $('#login').show();
  });

  $('div#support strong').html(getMsg('support_title'));
  $('p#support_message').html(getMsg('support_message'));
  $('a#support_link').attr('href', getMsg('donation_url'));
  $('button#support_button').html(getMsg('support_button'));

  $('div#social strong').html(getMsg('social_title'));

  $('div#mode_select strong').html(getMsg('mode_select'));

  $('span.mode_off_name').html(getMsg('mode_off'));
  $('span.mode_off_desc').html(getMsg('mode_off_description'));
  $('span.mode_normal_name').html(getMsg('mode_normal'));
  $('span.mode_normal_desc').html(getMsg('mode_normal_description'));

  $('div#faq').html(getMsg('faq'));
  $('div#feedback').html(getMsg('feedback'));
  $('div#rating').html(getMsg('rating'));
})();

// Preselect the default button
Settings.getCurrentMode().then((mode) => {
  switch (mode) {
    case Modes.OFF:
      $('label#off').addClass('active');
      break;
    default:
      $('label#normal').addClass('active');
      break;
  }
});


// Add version number to the footer
$('div#version small').html('Unblock Youku v' + chrome.runtime.getManifest().version);
// Clear the text on the browser icon after the user has clicked on the icon
Icon.clearIconText();


// Set up button actions
$('input#input_off').change(function() {
  console.group('Clicked on the button to change the mode to OFF...');
  Settings.setNewMode(Modes.OFF).then(() => {
    console.groupEnd();
    console.log('Finished changing the mode to OFF');
  });
});
$('input#input_normal').change(function() {
  console.group('Clicked on the button to change the mode to NORMAL...');
  Settings.setNewMode(Modes.NORMAL).then(() => {
    console.groupEnd();
    console.log('Finished changing the mode to NORMAL');
  });
});


// Enable tooltip
$('#tooltip').tooltip();
