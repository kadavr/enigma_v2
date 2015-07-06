#!/usr/bin/env perl

use utf8;
use Mojolicious::Lite;
use Time::HiRes;
use Crypt::Digest::MD5 qw( md5_hex );
use DBIx::RetryOverDisconnects;
use Config::INI::Reader;

use constant {
    TOO_BIG   => 1,
    TOO_SMALL => 2,

    #Size does matter after all. (Rammstein);
};

my $econf = Config::INI::Reader->read_file('./enigma.ini');

# CREATE TABLE enigma.enigmas (
#   ekey VARCHAR(32) NOT NULL,
#   evalue TEXT(400) NOT NULL,
#   deadline INTEGER(11) DEFAULT 0,
#   PRIMARY KEY (ekey)
# ) ENGINE=MyISAM DEFAULT CHARSET=utf8

my $dbh = DBIx::RetryOverDisconnects->connect(
    "DBI:mysql:mysql_socket=" . $econf->{mysql}->{sock} . ":database=enigma",
    $econf->{mysql}->{user},
    $econf->{mysql}->{password},
    {   ReconnectRetries  => 50,
        ReconnectInterval => 0.5,
        ReconnectTimeout  => 3,
        TxnRetries        => 25,
    }
);

app->secrets( [$econf->{enigma}->{secret}] );
app->mode( $econf->{enigma}->{mode} );

get '/' => sub {
    my $c = shift;
    my $enigmas = $c->session->{enigmas} ||= [];
    $c->stash(
        error       => $c->param('error'),
        enigmas     => $enigmas,
        has_enigmas => scalar(@$enigmas)
    );
    $c->render('enigma_index');
};

my @ttls = (
    0,
    3600,     #1h
    21600,    #6h
    43200,    #12h
    86400     #24h
);

get '/v/:key' => sub {
    my $c   = shift;
    my $key = $c->param('key');

    my ( $data, $deadline )
        = $dbh->selectrow_array(
        'SELECT evalue, deadline FROM enigmas WHERE ekey=?',
        {}, $key );
    unless ($data) {
        $c->reply->not_found;
        return;
    }
    if ( $deadline != 0 && $deadline < time ) {
        $dbh->do( 'DELETE FROM enigmas WHERE ekey=?', {}, $key );
        $c->reply->not_found;
        return;
    }
    if ( $deadline == 0 ) {
        $dbh->do( 'DELETE FROM enigmas WHERE ekey=?', {}, $key );
    }
    utf8::decode($data);
    $c->stash( deadline => $deadline, payload => $data );
    $c->render('enigma_view');
};

post '/new_cipher' => sub {
    my $c       = shift;
    my $data    = $c->param('data');
    my $ttl_idx = $c->param('ttl') || 0;

    utf8::encode($data) if utf8::is_utf8($data);

    my $key;

    my $calc_key = sub {
        md5_hex(
            ( $_[0] || '' ) . '' . Time::HiRes::time . '' . rand(100000) );
    };

    if ( length($data) == 0 ) {
        $c->redirect_to( "/?error=" . TOO_SMALL() );
        return;
    }
    elsif ( length($data) > 400 ) {
        $c->redirect_to( "/?error=" . TOO_BIG() );
        return;
    }
    else {
        $key = $calc_key->($data);
    }

    my $deadline = 0;
    if ( defined $ttl_idx && $ttls[$ttl_idx] ) {
        $deadline = time + $ttls[$ttl_idx];
    }

LOOP: {

        if ($dbh->selectrow_array(
                'SELECT 1 FROM enigmas WHERE ekey=?',
                {}, $key
            )
            )
        {
            $key = $calc_key->($data);
            goto LOOP;
        }
        else {
            $dbh->do( "INSERT INTO enigmas VALUES (?,?,?)",
                {}, $key, $data, $deadline );
        }
    }
    push @{ $c->session->{enigmas} }, "http://" . $econf->{enigma}->{host} . "/v/" . $key;

    $c->redirect_to('/');
};

#Garbage Collector...
if($econf->{enigma_gc}->{enabled}){
  Mojo::IOLoop->recurring(
      $econf->{enigma_gc}->{period} => sub {
          #simple GC
          app->log->debug("Starting GC");    #fucking idiot
          my $garbage = $dbh->selectall_arrayref("SELECT ekey FROM enigmas WHERE deadline < ?",{},time);
          foreach my $row (@$garbage){
            eval {$dbh->do( 'DELETE FROM enigmas WHERE ekey=?', {}, $row->[0] )};
            if($@){
              app->log->debug( "GC can't remove key " . $row->[0] . "; " . $@ );
            }else{
              app->log->debug( "GC removes key " . $row->[0] );
            }
          }
          app->log->debug("Stopping GC");
      }
  );
}

app->start;
__DATA__

@@ not_found.production.html.ep
% layout 'default';
% title 'Enigma Энигма: Ничего не найдено!';

<legend><a href="/">Enigma</a></legend>
<div class="col-md-2"></div>
<div class="col-md-8">
    <div class="alert alert-danger" role="alert"><strong>Not Found!</strong> The requested URL was not found on this server.</div>
</div>

@@ enigma_view.html.ep
% layout 'default';
% title 'Enigma Энигма';

<legend><a href="/">Enigma</a></legend>
<div class="col-md-2"></div>
<div class="col-md-8">
    <div class="panel panel-default">
        <div class="panel-heading"> The answer to enigma =) </div>
        <div class="container">
            <p><%= $payload %></p>
        </div>
    </div>
</div>

@@ enigma_index.html.ep
% layout 'default';
% title 'Enigma Энигма';

<form class="form-horizontal" action="/new_cipher" method="post">
<fieldset>

<!-- Form Name -->
<legend><a href="/">Enigma</a></legend>

<!-- Textarea -->
<div class="form-group">
  <label class="col-md-4 control-label" for="textarea">Text (maxlen 400)</label>
  <div class="col-md-4">                     
    <textarea class="form-control <%= ($error || 0 ) > 0 ? b('alert-danger') : () %>" id="textarea" name="data" maxlength="400"></textarea>
  </div>
</div>

<!-- Select Basic -->
<div class="form-group">
  <label class="col-md-4 control-label" for="selectbasic">TTL (time to live):</label>
  <div class="col-md-4">
    <select id="selectbasic" name="ttl" class="form-control">
      <option value="0">to first click</option>
      <option value="1">1 hour</option>
      <option value="2">6 hours</option>
      <option value="3">12 hours</option>
      <option value="4">1 day</option>
    </select>
  </div>
</div>

<!-- Button -->
<div class="form-group">
  <label class="col-md-4 control-label" for="singlebutton"></label>
  <div class="col-md-4">
    <button id="singlebutton" name="singlebutton" class="btn btn-primary">Create enigma</button>
  </div>
</div>

<!-- Enigmas -->
<div class="form-group">
    
  <label class="col-md-2 control-label" for="hack"></label>
  <div class="col-md-8">
    % if($has_enigmas){
    <div class="panel panel-default">
        <div class="panel-heading">Session enigmas</div>
        <ol class="list-group">
            % my $last = @$enigmas - 1;
            % while ( my ($i, $enigma) = each @$enigmas){
                <li class="list-group-item <%= $i == $last ? b('alert-success') : () %>" id="enigma-item-<%= $i %>" ><%= $enigma %></li>
            % }
        </ol>
    </div>
    % }
  </div>
</div>

</fieldset>
</form>



@@ layouts/default.html.ep
<!DOCTYPE html>
<html>
  <head>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css">
  <script src="//code.jquery.com/jquery-1.11.3.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
  <style>
  ol li.list-group-item { 
    list-style: decimal inside;
    display: list-item;
  }
  </style>
  <script type="text/javascript">
    $(function() {
        $("[id^=enigma-item]").click(function () {
           if (window.getSelection) {
              selection = window.getSelection();
              range = document.createRange();
              range.selectNodeContents(this);
              selection.removeAllRanges();
              selection.addRange(range);
            } else if (document.body.createTextRange) {
              range = document.body.createTextRange();
              range.moveToElementText(this);
              range.select();
            }
        })
    });
  </script>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">

  <meta name="description" content="Enigma: одноразовые ссылки, onetime urls.">
  <meta name="keywords" content="Enigma, Энигма, одноразовая, временная, секретная, сcылка, onetime, secret, url">
  <title><%= title %></title>
  </head>
  <body>
    <div class="container-fluid">
      <%= content %>
      <footer class="footer">
      <center><h5><a href="https://github.com/kadavr/enigma_v2">github</a></h5></center>
    </footer>
    </div>
  </body>
</html>
