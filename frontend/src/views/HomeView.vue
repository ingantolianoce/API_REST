<script setup lang="ts">
import { useAuth } from '../stores/auth'
const auth = useAuth()
</script>

<template>
  <h1>Inicio</h1>
  <p v-if="auth.me">Hola, {{ auth.me.fullName }} ({{ auth.me.roles.join(', ') }}).</p>
  <p v-if="auth.me && !auth.me.mfaEnabled">
    <RouterLink to="/activar-mfa">Active la verificación en dos pasos</RouterLink>
  </p>
</template>
